# Root-owned filesystem boundary for the delegated GitLab bootstrap credential.
require 'securerandom'
require 'io/nonblock'

BOOTSTRAP_ERROR_CATEGORIES = %w[
  arguments not_root unsafe_path invalid_credential_file storage_lock destination_exists
  runner_timeout runner_output runner_failed runner_protocol runner_io internal
  root_identity token_input root_user token_validation named_pat_exists
].freeze
RAILS_ERROR_CATEGORIES = %w[
  root_identity arguments token_input root_user token_validation named_pat_exists
  internal
].freeze

class BootstrapFailure < StandardError
  attr_reader :category

  def initialize(category)
    @category = category
    super(category)
  end
end

def fail_bootstrap(category)
  safe_category = BOOTSTRAP_ERROR_CATEGORIES.include?(category) ? category : 'internal'
  raise BootstrapFailure, safe_category
end

def lstat_or_nil(path)
  File.lstat(path)
rescue Errno::ENOENT
  nil
end

def validate_parent(parent)
  current = '/'
  parent.split('/').reject(&:empty?).each do |component|
    current = File.join(current, component)
    stat = File.lstat(current)
    fail_bootstrap('unsafe_path') if stat.symlink? || !stat.directory? || !stat.uid.zero?
    # Permit sticky root-owned shared ancestors such as /tmp, but no other
    # group/world-writable ancestor. The credential's own parent is stricter.
    writable = (stat.mode & 0o022) != 0
    sticky_root = stat.uid.zero? && (stat.mode & 0o1000) != 0
    fail_bootstrap('unsafe_path') if writable && !sticky_root
  end
  stat = File.lstat(parent)
  fail_bootstrap('unsafe_path') unless stat.uid.zero? && (stat.mode & 0o7777) == 0o700
end

def validate_credential_stat(stat)
  fail_bootstrap('invalid_credential_file') unless
    stat.file? && stat.uid.zero? && (stat.mode & 0o7777) == 0o600
end

def validate_new_credential_stat(stat)
  validate_credential_stat(stat)
  fail_bootstrap('invalid_credential_file') unless stat.gid.zero? && stat.nlink == 1
end

def read_credential(path, expected_stat = nil)
  flags = File::RDONLY
  flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
  File.open(path, flags) do |file|
    stat = file.stat
    validate_credential_stat(stat)
    if expected_stat && (stat.dev != expected_stat.dev || stat.ino != expected_stat.ino)
      fail_bootstrap('unsafe_path')
    end
    value = file.read(4097)
    fail_bootstrap('invalid_credential_file') if value.bytesize > 4096
    value = value.strip
    fail_bootstrap('invalid_credential_file') if value.empty?
    value
  end
rescue Errno::ELOOP, Errno::EACCES
  fail_bootstrap('invalid_credential_file')
end

def fsync_directory(parent)
  File.open(parent, File::RDONLY) { |directory| directory.fsync }
end

def terminate_group(pid)
  Process.kill('TERM', -pid)
rescue SystemCallError
  nil
end

def kill_group(pid)
  Process.kill('KILL', -pid)
rescue SystemCallError
  nil
end

def cleanup_child(pid, reaped)
  return true if reaped
  begin
    terminate_group(pid)
    sleep 0.25
    kill_group(pid)
  ensure
    begin
      Process.waitpid(pid)
    rescue Errno::ECHILD
      nil
    end
  end
  true
end

def run_rails(mode, token)
  expected = "LUDUS_BOOTSTRAP_V1 #{mode == 'create' ? 'CREATED' : 'VALIDATED'}\n"
  input_r, input_w = IO.pipe
  output_r, output_w = IO.pipe
  pid = nil
  reaped = false
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 120

  begin
    pid = Process.spawn(
      { 'NO_PRIVILEGE_DROP' => nil },
      '/opt/gitlab/bin/gitlab-rails', 'runner',
      '/usr/local/sbin/ludus-gitlab-bootstrap-api-token-rails.rb', mode,
      in: input_r, out: output_w, err: File::NULL, pgroup: true, close_others: true
    )
    input_r.close
    output_w.close
    input_w.nonblock = true
    output_r.nonblock = true

    input = token.b
    input_offset = 0
    input_open = true
    output_open = true
    output = +''.b
    oversized = false
    status = nil

    while input_open || output_open || !reaped
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      fail_bootstrap('runner_timeout') if now >= deadline

      # Keep the leader unreaped while any pipe remains open. If a descendant
      # inherited stdout, timeout cleanup can still signal its process group
      # before reaping the leader and risking PID/PGID reuse.
      if !reaped && !input_open && !output_open
        waited, status = Process.waitpid2(pid, Process::WNOHANG)
        reaped = true if waited
      end

      readers = output_open ? [output_r] : []
      writers = input_open ? [input_w] : []
      ready = IO.select(readers, writers, nil, [deadline - now, 0.1].min)
      next unless ready

      if input_open && ready[1].include?(input_w)
        begin
          written = input_w.write_nonblock(input.byteslice(input_offset..), exception: false)
          unless written == :wait_writable
            input_offset += written
            if input_offset >= input.bytesize
              input_w.close
              input_open = false
            end
          end
        rescue Errno::EPIPE
          input_w.close
          input_open = false
        end
      end

      if output_open && ready[0].include?(output_r)
        chunk = output_r.read_nonblock(512, exception: false)
        if chunk.nil?
          output_r.close
          output_open = false
        elsif chunk != :wait_readable
          if output.bytesize + chunk.bytesize <= 256
            output << chunk
          else
            oversized = true
          end
        end
      end
    end

    fail_bootstrap('runner_output') if oversized
    if status&.success?
      fail_bootstrap('runner_protocol') unless output == expected
    else
      category = RAILS_ERROR_CATEGORIES.find do |candidate|
        output == "LUDUS_BOOTSTRAP_ERROR #{candidate}\n"
      end
      fail_bootstrap(category) if category
      fail_bootstrap(output.empty? ? 'runner_failed' : 'runner_protocol')
    end
  rescue BootstrapFailure
    raise
  rescue StandardError
    fail_bootstrap('runner_io')
  ensure
    begin
      [input_r, input_w, output_r, output_w].each do |io|
        begin
          io.close unless io.nil? || io.closed?
        rescue StandardError
          nil
        end
      end
    ensure
      if pid && !reaped
        reaped = cleanup_child(pid, reaped)
      end
    end
  end
end

def remove_owned_temp(path, stat)
  return unless path && stat
  current = lstat_or_nil(path)
  return unless current && current.file? && current.dev == stat.dev && current.ino == stat.ino
  File.unlink(path)
  true
rescue Errno::ENOENT
  false
end

begin
  fail_bootstrap('not_root') unless Process.euid.zero?
  fail_bootstrap('arguments') unless ARGV.length == 1
  token_path = ARGV.fetch(0)
  fail_bootstrap('unsafe_path') unless token_path.start_with?('/') && !token_path.include?("\0")
  token_path = File.expand_path(token_path)
  parent = File.dirname(token_path)
  basename = File.basename(token_path)
  fail_bootstrap('unsafe_path') if basename.empty? || basename == '.' || basename == '..'
  validate_parent(parent)

  File.open(parent, File::RDONLY) do |directory|
    fail_bootstrap('storage_lock') unless directory.flock(File::LOCK_EX | File::LOCK_NB)
    target_stat = lstat_or_nil(token_path)
    if target_stat
      validate_credential_stat(target_stat)
      token = read_credential(token_path, target_stat)
      run_rails('validate', token)
    else
      token = SecureRandom.hex(32)
      temporary_path = File.join(parent, ".#{basename}.tmp.#{Process.pid}.#{SecureRandom.hex(12)}")
      temporary_stat = nil
      published = false
      begin
        flags = File::WRONLY | File::CREAT | File::EXCL
        flags |= File::NOFOLLOW if File.const_defined?(:NOFOLLOW)
        File.open(temporary_path, flags, 0o600) do |file|
          temporary_stat = file.stat
          file.chown(0, 0)
          temporary_stat = file.stat
          validate_new_credential_stat(temporary_stat)
          file.write("#{token}\n")
          file.flush
          file.fsync
        end

        run_rails('create', token)

        fail_bootstrap('destination_exists') if lstat_or_nil(token_path)
        begin
          File.link(temporary_path, token_path)
        rescue Errno::EEXIST
          fail_bootstrap('destination_exists')
        end
        published = true
        fail_bootstrap('internal') unless remove_owned_temp(temporary_path, temporary_stat)
        temporary_path = nil
        final_stat = File.lstat(token_path)
        validate_new_credential_stat(final_stat)
        fail_bootstrap('invalid_credential_file') unless read_credential(token_path, final_stat) == token
        fsync_directory(parent)
      ensure
        remove_owned_temp(temporary_path, temporary_stat) unless published
      end
    end
  end
rescue BootstrapFailure => error
  warn "LUDUS_BOOTSTRAP_ERROR #{error.category}"
  exit 1
rescue StandardError
  warn 'LUDUS_BOOTSTRAP_ERROR internal'
  exit 1
end

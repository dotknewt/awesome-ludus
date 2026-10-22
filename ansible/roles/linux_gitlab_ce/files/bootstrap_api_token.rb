# Generates one root-owned delegated PAT, or verifies the persisted copy.
# This script intentionally never prints the token.
require 'securerandom'

token_path = ARGV.fetch(0)
token_name = 'Ludus delegated runner bootstrap'
required_scopes = %w[api create_runner]
root = User.find_by_username('root')
abort 'Cannot create bootstrap credential: GitLab root user is unavailable.' unless root

named_tokens = root.personal_access_tokens.where(name: token_name)

validate_token = lambda do |raw_token|
  token = PersonalAccessToken.find_by_token(raw_token)
  unless token && token.user_id == root.id && token.name == token_name &&
         !token.revoked? && !token.expired? && (required_scopes - token.scopes.map(&:to_s)).empty?
    abort 'Persisted GitLab bootstrap credential is invalid, expired, revoked, or missing required scopes; recover explicitly.'
  end
end

target_stat = begin
  File.lstat(token_path)
rescue Errno::ENOENT
  nil
end

if target_stat
  stat = target_stat
  unless stat.file? && stat.uid.zero? && (stat.mode & 0o777) == 0o600
    abort 'Persisted GitLab bootstrap credential must be a root-owned regular file with mode 0600; recover explicitly.'
  end
  raw_token = File.read(token_path).strip
  abort 'Persisted GitLab bootstrap credential is empty; recover explicitly.' if raw_token.empty?
  validate_token.call(raw_token)
elsif named_tokens.exists?
  abort 'GitLab bootstrap PAT exists but its persisted credential file is missing; restore it or perform explicit operator recovery.'
else
  raw_token = SecureRandom.hex(32)
  pat = root.personal_access_tokens.create!(
    name: token_name,
    scopes: required_scopes,
    expires_at: 365.days.from_now
  )
  pat.set_token(raw_token)
  pat.save!

  temporary_path = "#{token_path}.tmp.#{$$}"
  begin
    File.open(temporary_path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
      file.write("#{raw_token}\n")
      file.flush
      file.fsync
    end
    File.chown(0, 0, temporary_path)
    File.rename(temporary_path, token_path)
    final_stat = File.lstat(token_path)
    unless final_stat.file? && final_stat.uid.zero? && (final_stat.mode & 0o777) == 0o600
      abort 'New GitLab bootstrap credential failed root-owned regular-file mode-0600 verification.'
    end
    File.open(File.dirname(token_path), 'r') { |directory| directory.fsync }
  ensure
    File.delete(temporary_path) if File.exist?(temporary_path)
  end
end

puts 'GitLab delegated bootstrap credential is available.'

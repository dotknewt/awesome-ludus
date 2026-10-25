# Non-secret Rails-side PAT operations. The root wrapper owns all filesystem IO.
RAILS_ERROR_CATEGORIES = %w[
  root_identity arguments token_input root_user token_validation named_pat_exists internal
].freeze

def bootstrap_fail(category)
  safe_category = RAILS_ERROR_CATEGORIES.include?(category) ? category : 'internal'
  STDOUT.write("LUDUS_BOOTSTRAP_ERROR #{safe_category}\n")
  exit 1
end

begin
  bootstrap_fail('root_identity') if Process.euid.zero?
  bootstrap_fail('arguments') unless ARGV.length == 1 && %w[create validate].include?(ARGV.fetch(0))
  operation = ARGV.fetch(0)

  input = STDIN.read(4097)
  bootstrap_fail('token_input') if input.bytesize > 4096
  token = input.strip
  bootstrap_fail('token_input') if token.empty? || STDIN.read(1)

  token_name = 'Ludus delegated runner bootstrap'
  required_scopes = %w[api create_runner]
  root = User.find_by_username('root')
  bootstrap_fail('root_user') unless root

  validate_token = lambda do |candidate|
    stored = PersonalAccessToken.find_by_token(candidate)
    valid = stored && stored.user_id == root.id && stored.name == token_name &&
            !stored.revoked? && !stored.expired? &&
            (required_scopes - stored.scopes.map(&:to_s)).empty?
    bootstrap_fail('token_validation') unless valid
  end

  if operation == 'validate'
    validate_token.call(token)
    puts 'LUDUS_BOOTSTRAP_V1 VALIDATED'
  else
    named_tokens = root.personal_access_tokens.where(name: token_name)
    bootstrap_fail('named_pat_exists') if named_tokens.exists?

    PersonalAccessToken.transaction do
      pat = root.personal_access_tokens.build(
        name: token_name,
        scopes: required_scopes,
        expires_at: 365.days.from_now
      )
      pat.set_token(token)
      pat.save!
      validate_token.call(token)
    end
    # Emit only after the creation transaction has committed.
    puts 'LUDUS_BOOTSTRAP_V1 CREATED'
  end
rescue StandardError
  bootstrap_fail('internal')
end

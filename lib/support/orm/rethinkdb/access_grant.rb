
module Doorkeeper
  class AccessGrant
    include NoBrainer::Document

    table_config name: 'doorkeeper_grant'

    include OAuth::Helpers
    include Models::Expirable
    include Models::Revocable
    include Models::Accessible
    include Models::Scopes

    include Timestamps

    belongs_to  :application, class_name: 'Doorkeeper::Application'

    field :resource_owner_id, type: String
    field :token,             type: String, uniq: true, index: true
    field :scopes,            type: String
    field :redirect_uri,      type: String

    field :expires_in,        type: Integer
    field :ttl,               type: Integer
    
    # PKCE support
    field :code_challenge,        type: String
    field :code_challenge_method, type: String

    class << self
      def by_token(token)
        where(token: token).first
      end
      
      # @param code_verifier [#to_s] a one time use value (any object that responds to `#to_s`)
      #
      # @return [#to_s] An encoded code challenge based on the provided verifier
      # suitable for PKCE validation
      #
      def generate_code_challenge(code_verifier)
        padded_result = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier))
        padded_result.split("=")[0] # Remove any trailing '='
      end
      
      def pkce_supported?
        true
      end
      
      ##
      # Determines the secret storing transformer
      # Unless configured otherwise, uses the plain secret strategy
      #
      # @return [Doorkeeper::SecretStoring::Base]
      #
      def secret_strategy
        ::Doorkeeper.config.token_secret_strategy
      end

      ##
      # Determine the fallback storing strategy
      # Unless configured, there will be no fallback
      #
      # @return [Doorkeeper::SecretStoring::Base]
      #
      def fallback_secret_strategy
        ::Doorkeeper.config.token_secret_fallback_strategy
      end
    end

    validates :resource_owner_id, :application, :token, :expires_in, :redirect_uri, presence: true
    before_validation :generate_token, on: :create

    def transaction; yield; end
    def lock!; end
    
    def uses_pkce?
      self.code_challenge.present?
    end
    
    # We keep a volatile copy of the raw token for initial communication
    # The stored refresh_token may be mapped and not available in cleartext.
    #
    # Some strategies allow restoring stored secrets (e.g. symmetric encryption)
    # while hashing strategies do not, so you cannot rely on this value
    # returning a present value for persisted tokens.
    def plaintext_token
      if secret_strategy.allows_restoring_secrets?
        secret_strategy.restore_secret(self, :token)
      else
        @raw_token
      end
    end

    private

    # Generates token value with UniqueToken class.
    #
    # @return [String] token value
    #
    def generate_token
      self.ttl = self.created_at + self.expires_in + 30 if self.created_at && self.expires_in
      if self.token.blank?
        @raw_token = Doorkeeper::OAuth::Helpers::UniqueToken.generate
        secret_strategy.store_secret(self, :token, @raw_token)
      end
    end
  end
end

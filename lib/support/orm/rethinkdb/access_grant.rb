
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
    end

    validates :resource_owner_id, :application, :token, :expires_in, :redirect_uri, presence: true
    before_validation :generate_token, on: :create

    def transaction; yield; end
    def lock!; end
    
    def uses_pkce?
      self.code_challenge.present?
    end

    private

    # Generates token value with UniqueToken class.
    #
    # @return [String] token value
    #
    def generate_token
      self.ttl = self.created_at + self.expires_in + 30 if self.created_at && self.expires_in
      self.token = UniqueToken.generate if self.token.blank?
    end
  end
end

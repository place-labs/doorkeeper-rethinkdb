
module Doorkeeper
  class AccessGrant
    include NoBrainer::Document

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

    class << self
      def by_token(token)
        where(token: token).first
      end
    end

    validates :resource_owner_id, :application, :token, :expires_in, :redirect_uri, presence: true
    before_validation :generate_token, on: :create

    def transaction; yield; end
    def lock!; end

    private

    # Generates token value with UniqueToken class.
    #
    # @return [String] token value
    #
    def generate_token
      self.ttl = self.created_at + self.expires_in + 30
      self.token = UniqueToken.generate if self.token.blank?
    end
  end
end

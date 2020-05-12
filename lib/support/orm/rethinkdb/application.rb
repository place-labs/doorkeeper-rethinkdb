
# Load these before the has_many
require File.expand_path("../access_grant", __FILE__)
require File.expand_path("../access_token", __FILE__)

# Required for Rails 6 support
require "doorkeeper/orm/active_record/redirect_uri_validator"

module Doorkeeper
  class Application
    include NoBrainer::Document

    table_config name: 'doorkeeper_app'

    include OAuth::Helpers
    include Models::Scopes

    field :name, type: String
    field :uid, type: String, uniq: true, index: true
    field :secret, type: String
    field :scopes, type: String
    field :redirect_uri, type: String

    field :skip_authorization, type: Boolean, default: false
    field :confidential, type: Boolean, default: false

    field :owner_id, type: String

    validates :owner, presence: true, if: :validate_owner?
    def validate_owner?
      Doorkeeper.configuration.confirm_application_owner?
    end

    has_many :access_grants, dependent: :destroy, class_name: 'Doorkeeper::AccessGrant'
    has_many :access_tokens, dependent: :destroy, class_name: 'Doorkeeper::AccessToken'

    class << self
      def by_uid(uid)
        where(uid: uid).first
      end

      def by_uid_and_secret(uid, secret)
        where(uid: uid, secret: secret).first
      end

      def authorized_for(resource_owner)
        AccessToken.find_by_resource_owner_id(resource_owner.id).collect(&:application)
      end
    end
    
    def authorized_for_resource_owner?(resource_owner)
      Doorkeeper.configuration.authorize_resource_owner_for_client.call(self, resource_owner)
    end

    private

    validates :name, :secret, :uid, presence: true
    validates :redirect_uri, "doorkeeper/redirect_uri": true
    validates :confidential, inclusion: { in: [true, false] }

    before_validation :generate_uid, :generate_secret, on: :create

    def has_scopes?
      true
    end

    def generate_uid
      self.uid = UniqueToken.generate if uid.blank?
    end

    def generate_secret
      self.secret = UniqueToken.generate if secret.blank?
    end
  end
end

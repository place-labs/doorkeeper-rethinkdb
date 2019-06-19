require 'date'

module Doorkeeper
  module Rethinkdb
    module Timestamps
      extend ActiveSupport::Concern

      included do
        field :revoked_at, type: Integer
        field :created_at, type: Integer, default: ->{ Time.now.to_i + 1 }
      end

      def revoked_at
        revoked = super
        Time.at(revoked) unless revoked.nil?
      end

      def revoked_at=(time)
        if time
          number = time.is_a?(Numeric) ? time.to_i : time.to_time.to_i
          super number
        else
          super nil
        end
      end

      def created_at
        Time.at(super)
      end
    end
  end
end

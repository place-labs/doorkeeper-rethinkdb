
module Doorkeeper
  # Reopen to align with NoBrainer's exclusively `super` overrides.
  # ORM is thrust into an infinite loop, otherwise.
  module Models::Scopes
    def scopes
      OAuth::Scopes.from_string(super)
    end

    def scopes=(value)
      super Array(value).join(" ")
    end

    def scopes_string
      self._read_attribute(:scopes)
    end

    def includes_scope?(*required_scopes)
      required_scopes.blank? || required_scopes.any? { |scope| scopes.exists?(scope.to_s) }
    end
  end
end
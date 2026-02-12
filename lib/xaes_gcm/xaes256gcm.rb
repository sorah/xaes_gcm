# frozen_string_literal: true

module XaesGcm
  module Xaes256gcm
    KEY_SIZE = 32
    NONCE_SIZE = 24

    DerivedKey = Data.define(:key, :nonce) do
      # Data.define#inspect doesn't use instance_variables_to_inspect
      def inspect
        "#<#{self.class}>"
      end
      alias to_s inspect
    end
  end
end

require_relative "xaes256gcm/key"

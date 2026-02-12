# frozen_string_literal: true

require "openssl"
require_relative "xaes_gcm/version"

module XaesGcm
  class Error < StandardError; end

  KEY_SIZE = 32
  NONCE_SIZE = 24

  # Detect instance_variables_to_inspect support (Ruby feature #13555)
  HAVE_INSTANCE_VARIABLES_TO_INSPECT = begin
    klass = Class.new do
      def initialize = @secret = true
      def instance_variables_to_inspect = []
    end
    !klass.new.inspect.include?("@secret")
  end

  DerivedKey = Data.define(:key, :nonce) do
    # Data.define#inspect doesn't use instance_variables_to_inspect
    def inspect
      "#<#{self.class}>"
    end
    alias to_s inspect
  end
end

require_relative "xaes_gcm/key"

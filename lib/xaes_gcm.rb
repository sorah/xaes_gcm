# frozen_string_literal: true

require "openssl"
require_relative "xaes_gcm/version"

module XaesGcm
  class Error < StandardError; end

  # Detect instance_variables_to_inspect support (Ruby feature #13555)
  HAVE_INSTANCE_VARIABLES_TO_INSPECT = begin
    klass = Class.new do
      def initialize = @secret = true
      def instance_variables_to_inspect = []
    end
    !klass.new.inspect.include?("@secret")
  end

  def self.key(key_length, key)
    raise ArgumentError, "unsupported key length: #{key_length}" unless key_length == 256
    Xaes256gcm::Key.new(key)
  end
end

require_relative "xaes_gcm/xaes256gcm"

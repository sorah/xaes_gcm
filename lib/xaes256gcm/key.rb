# frozen_string_literal: true

module Xaes256gcm
  class Key
    def initialize(key)
      raise ArgumentError, "key must be #{KEY_SIZE} bytes" unless key.bytesize == KEY_SIZE

      @cipher = OpenSSL::Cipher.new('aes-256-ecb')
      @cipher.encrypt
      @cipher.padding = 0
      @cipher.key = key

      # L = AES-256-ECB_K(0^128)
      l = @cipher.update("\x00" * 16) + @cipher.final

      # K1: shift L left by 1 bit, XOR last byte with 0x87 if MSB was set
      msb = l.getbyte(0) >> 7
      k1_bytes = Array.new(16) do |i|
        next_bit = (i < 15) ? (l.getbyte(i + 1) >> 7) : 0
        ((l.getbyte(i) << 1) | next_bit) & 0xFF
      end
      k1_bytes[-1] ^= 0x87 & -(msb & 1)
      @k1 = k1_bytes.pack('C*')
      @cipher.freeze
    end

    if HAVE_INSTANCE_VARIABLES_TO_INSPECT
      def instance_variables_to_inspect = []
    else
      def inspect
        "#<#{self.class}>"
      end
      alias to_s inspect
    end

    def apply(cipher, nonce: OpenSSL::Random.random_bytes(NONCE_SIZE))
      raise ArgumentError, "cipher must be AES-256-GCM" unless cipher.name == "AES-256-GCM"

      dk = derive_key(nonce:)
      cipher.key = dk.key
      cipher.iv = dk.nonce
      nonce
    end

    def derive_key(nonce:)
      raise ArgumentError, "nonce must be #{NONCE_SIZE} bytes" unless nonce.bytesize == NONCE_SIZE

      n12 = nonce.b[0, 12]

      m1 = "\x00\x01X\x00".b + n12
      m2 = "\x00\x02X\x00".b + n12

      m1_xored = xor_blocks(m1, @k1)
      m2_xored = xor_blocks(m2, @k1)

      cipher = @cipher.dup
      cipher.reset
      derived = cipher.update(m1_xored + m2_xored) + cipher.final

      DerivedKey.new(key: derived, nonce: nonce.b[12, 12])
    end

    private

    def xor_blocks(a, b)
      a_bytes = a.unpack('C*')
      b_bytes = b.unpack('C*')
      a_bytes.length.times { |i| a_bytes[i] ^= b_bytes[i] }
      a_bytes.pack('C*')
    end
  end
end

# frozen_string_literal: true

require "fiddle"

# SHAKE-128 XOF via OpenSSL's EVP_DigestSqueeze (OpenSSL 3.3+) through fiddle.
# Supports both streaming squeeze (for deterministic RNG) and update+squeeze
# (for accumulating a digest).
module ShakeHelper
  AVAILABLE = begin
    libcrypto = Fiddle.dlopen("libcrypto.so")
    EVP_MD_FETCH = Fiddle::Function.new(libcrypto["EVP_MD_fetch"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOIDP)
    EVP_MD_CTX_NEW = Fiddle::Function.new(libcrypto["EVP_MD_CTX_new"], [], Fiddle::TYPE_VOIDP)
    EVP_DIGEST_INIT_EX = Fiddle::Function.new(libcrypto["EVP_DigestInit_ex"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)
    EVP_DIGEST_UPDATE = Fiddle::Function.new(libcrypto["EVP_DigestUpdate"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_INT)
    EVP_DIGEST_SQUEEZE = Fiddle::Function.new(libcrypto["EVP_DigestSqueeze"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_INT)
    EVP_MD_CTX_FREE = Fiddle::Function.new(libcrypto["EVP_MD_CTX_free"], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID)
    SHAKE128_MD = EVP_MD_FETCH.call(nil, "SHAKE128", nil)
    true
  rescue Fiddle::DLError
    false
  end

  class Shake128
    def initialize
      raise "ShakeHelper not available (requires OpenSSL 3.3+)" unless AVAILABLE
      @ctx = ShakeHelper::EVP_MD_CTX_NEW.call
      raise "EVP_MD_CTX_new failed" if @ctx.null?
      ret = ShakeHelper::EVP_DIGEST_INIT_EX.call(@ctx, ShakeHelper::SHAKE128_MD, nil)
      raise "EVP_DigestInit_ex failed" unless ret == 1
    end

    def update(data)
      ret = ShakeHelper::EVP_DIGEST_UPDATE.call(@ctx, data, data.bytesize)
      raise "EVP_DigestUpdate failed" unless ret == 1
      self
    end

    def squeeze(n)
      buf = Fiddle::Pointer.malloc(n)
      ret = ShakeHelper::EVP_DIGEST_SQUEEZE.call(@ctx, buf, n)
      raise "EVP_DigestSqueeze failed" unless ret == 1
      buf[0, n]
    end

    def close
      ShakeHelper::EVP_MD_CTX_FREE.call(@ctx) if @ctx
      @ctx = nil
    end
  end
end

RSpec.describe Xaes256gcm do
  it "has a version number" do
    expect(Xaes256gcm::VERSION).not_to be_nil
  end

  describe "constants" do
    it "defines KEY_SIZE as 32" do
      expect(Xaes256gcm::KEY_SIZE).to eq(32)
    end

    it "defines NONCE_SIZE as 24" do
      expect(Xaes256gcm::NONCE_SIZE).to eq(24)
    end
  end

  describe Xaes256gcm::Key do
    describe "#initialize" do
      it "raises ArgumentError for wrong key size" do
        expect { Xaes256gcm::Key.new("\x00" * 16) }.to raise_error(ArgumentError, /key must be 32 bytes/)
        expect { Xaes256gcm::Key.new("\x00" * 33) }.to raise_error(ArgumentError, /key must be 32 bytes/)
      end

      it "accepts a 32-byte key" do
        expect { Xaes256gcm::Key.new("\x00" * 32) }.not_to raise_error
      end
    end

    describe "#apply" do
      let(:key) { Xaes256gcm::Key.new("\x01" * 32) }
      let(:nonce) { "ABCDEFGHIJKLMNOPQRSTUVWX" }

      it "raises ArgumentError for non AES-256-GCM cipher" do
        cipher = OpenSSL::Cipher.new("aes-128-gcm")
        cipher.encrypt
        expect { key.apply(cipher, nonce:) }.to raise_error(ArgumentError, /cipher must be AES-256-GCM/)
      end

      it "sets key and iv on the cipher and returns the nonce" do
        cipher = OpenSSL::Cipher.new("aes-256-gcm")
        cipher.encrypt
        returned_nonce = key.apply(cipher, nonce:)
        cipher.auth_data = ""
        ct = cipher.update("XAES-256-GCM") + cipher.final + cipher.auth_tag
        expect(ct.unpack1("H*")).to eq("ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271")
        expect(returned_nonce).to eq(nonce)
      end

      it "generates a random nonce by default" do
        cipher = OpenSSL::Cipher.new("aes-256-gcm")
        cipher.encrypt
        returned_nonce = key.apply(cipher)
        expect(returned_nonce.bytesize).to eq(Xaes256gcm::NONCE_SIZE)
      end
    end

    describe "#derive_key" do
      it "raises RuntimeError without enable_hazmat!" do
        key = Xaes256gcm::Key.new("\x00" * 32)
        expect { key.derive_key(nonce: "\x00" * 24) }.to raise_error(RuntimeError, /hazmat/)
      end

      it "raises ArgumentError for wrong nonce size" do
        key = Xaes256gcm::Key.new("\x00" * 32)
        key.enable_hazmat!
        expect { key.derive_key(nonce: "\x00" * 12) }.to raise_error(ArgumentError, /nonce must be 24 bytes/)
        expect { key.derive_key(nonce: "\x00" * 25) }.to raise_error(ArgumentError, /nonce must be 24 bytes/)
      end

      context "test vector 1 (MSB(L)=0, key=0x01*32)" do
        let(:key) { Xaes256gcm::Key.new("\x01" * 32).enable_hazmat! }
        let(:nonce) { "ABCDEFGHIJKLMNOPQRSTUVWX" }
        let(:dk) { key.derive_key(nonce:) }

        it "derives the correct key" do
          expect(dk.key.unpack1("H*")).to eq("c8612c9ed53fe43e8e005b828a1631a0bbcb6ab2f46514ec4f439fcfd0fa969b")
        end

        it "derives the correct nonce (last 12 bytes of input nonce)" do
          expect(dk.nonce).to eq("MNOPQRSTUVWX")
        end

        it "produces the correct ciphertext with AES-256-GCM" do
          cipher = OpenSSL::Cipher.new("aes-256-gcm")
          cipher.encrypt
          cipher.key = dk.key
          cipher.iv = dk.nonce
          cipher.auth_data = ""
          ct = cipher.update("XAES-256-GCM") + cipher.final + cipher.auth_tag
          expect(ct.unpack1("H*")).to eq("ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271")
        end
      end

      context "test vector 2 (MSB(L)=1, key=0x03*32)" do
        let(:key) { Xaes256gcm::Key.new("\x03" * 32).enable_hazmat! }
        let(:nonce) { "ABCDEFGHIJKLMNOPQRSTUVWX" }
        let(:dk) { key.derive_key(nonce:) }

        it "derives the correct key" do
          expect(dk.key.unpack1("H*")).to eq("e9c621d4cdd9b11b00a6427ad7e559aeedd66b3857646677748f8ca796cb3fd8")
        end

        it "derives the correct nonce" do
          expect(dk.nonce).to eq("MNOPQRSTUVWX")
        end

        it "produces the correct ciphertext with AES-256-GCM and AAD" do
          cipher = OpenSSL::Cipher.new("aes-256-gcm")
          cipher.encrypt
          cipher.key = dk.key
          cipher.iv = dk.nonce
          cipher.auth_data = "c2sp.org/XAES-256-GCM"
          ct = cipher.update("XAES-256-GCM") + cipher.final + cipher.auth_tag
          expect(ct.unpack1("H*")).to eq("986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d")
        end
      end

      context "accumulated randomized test (10,000 iterations)" do
        before { pending "requires OpenSSL 3.3+ (EVP_DigestSqueeze)" unless ShakeHelper::AVAILABLE }

        it "produces the expected SHAKE-128 digest over all ciphertexts" do
          iterations = 10_000
          expected = "e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939"

          s = ShakeHelper::Shake128.new
          d = ShakeHelper::Shake128.new

          iterations.times do
            key_bytes = s.squeeze(32)
            nonce_bytes = s.squeeze(24)
            pt_len = s.squeeze(1).getbyte(0)
            plaintext = pt_len > 0 ? s.squeeze(pt_len) : "".b
            aad_len = s.squeeze(1).getbyte(0)
            aad = aad_len > 0 ? s.squeeze(aad_len) : "".b

            xkey = Xaes256gcm::Key.new(key_bytes)
            xkey.enable_hazmat!
            dk = xkey.derive_key(nonce: nonce_bytes)

            cipher = OpenSSL::Cipher.new("aes-256-gcm")
            cipher.encrypt
            cipher.key = dk.key
            cipher.iv = dk.nonce
            cipher.auth_data = aad
            ciphertext = cipher.update(plaintext) + cipher.final + cipher.auth_tag

            # Verify round-trip decryption
            decipher = OpenSSL::Cipher.new("aes-256-gcm")
            decipher.decrypt
            decipher.key = dk.key
            decipher.iv = dk.nonce
            decipher.auth_tag = ciphertext[-16..]
            decipher.auth_data = aad
            decrypted = decipher.update(ciphertext[0...-16]) + decipher.final
            expect(decrypted).to eq(plaintext)

            d.update(ciphertext)
          end

          expect(d.squeeze(32).unpack1("H*")).to eq(expected)
        ensure
          s&.close
          d&.close
        end
      end
    end
  end
end

# xaes_gcm

Ruby implementation of [XAES-256-GCM](https://c2sp.org/XAES-256-GCM), an extended-nonce AEAD built on AES-256-GCM.

XAES-256-GCM uses 192-bit (24-byte) nonces instead of AES-256-GCM's 96-bit nonces. The longer nonce makes it safe to generate nonces randomly for a practically unlimited number of messages, without risking nonce reuse.

This gem implements the key and nonce derivation step of XAES-256-GCM. It derives a standard AES-256-GCM key and nonce from the extended inputs, which you then use with Ruby's built-in `OpenSSL::Cipher` for encryption and decryption.

## Security Warning

> [!CAUTION]
> No security audits of this gem have ever been performed. USE AT YOUR OWN RISK!

## Installation

```bash
bundle add xaes_gcm
```

Or install directly:

```bash
gem install xaes_gcm
```

## Usage

```ruby
require "xaes_gcm"

# Create a reusable key (precomputes the AES key schedule and subkey)
key = OpenSSL::Random.random_bytes(XaesGcm::Xaes256gcm::KEY_SIZE) # 32 bytes
xkey = XaesGcm.key(256, key)

# Encrypt (generates a random 192-bit nonce by default)
cipher = OpenSSL::Cipher.new("aes-256-gcm")
cipher.encrypt
nonce = xkey.apply(cipher)
cipher.auth_data = "optional authenticated data"
ciphertext = cipher.update(plaintext) + cipher.final
tag = cipher.auth_tag

# Decrypt (pass the same nonce used for encryption)
decipher = OpenSSL::Cipher.new("aes-256-gcm")
decipher.decrypt
xkey.apply(decipher, nonce:)
decipher.auth_tag = tag
decipher.auth_data = "optional authenticated data"
plaintext = decipher.update(ciphertext) + decipher.final
```

`Key#apply` generates a random nonce, derives the AES-256-GCM key and nonce, sets them on the cipher, and returns the 24-byte nonce. Pass the same nonce back for decryption. `Key` precomputes the AES key schedule and subkey, so reuse the same instance when encrypting multiple messages under the same key.

## Alternative gems

There's alternative gem `xaes_256_gcm`: https://github.com/vcsjones/xaes-256-gcm-ruby

Key differences:

- Smaller code footprint
  - Leaving OpenSSL::Cipher setup to the user
- Accumulated randomized test vectors are included in the test suite
- rbs signature

## License

The gem is available as open source under the terms of the [BSD 1-Clause License](https://opensource.org/licenses/BSD-1-Clause).

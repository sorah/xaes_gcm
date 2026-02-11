# frozen_string_literal: true

require_relative "lib/xaes256gcm/version"

Gem::Specification.new do |spec|
  spec.name = "xaes256gcm"
  spec.version = Xaes256gcm::VERSION
  spec.authors = ["Sorah Fukumori"]
  spec.email = ["sorah@ivry.jp"]

  spec.summary = "XAES-256-GCM extended-nonce AEAD key derivation"
  spec.description = "Ruby implementation of XAES-256-GCM (c2sp.org/XAES-256-GCM), an extended-nonce AEAD built on AES-256-GCM. Derives standard AES-256-GCM keys and nonces from 256-bit keys and 192-bit nonces."
  spec.homepage = "https://github.com/sorah/xaes256gcm"
  spec.license = "BSD-1-Clause"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sorah/xaes256gcm"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore .rspec spec/ .github/])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end

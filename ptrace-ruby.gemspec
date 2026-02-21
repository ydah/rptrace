# frozen_string_literal: true

require_relative "lib/ptrace/version"

Gem::Specification.new do |spec|
  spec.name = "ptrace-ruby"
  spec.version = Ptrace::VERSION
  spec.authors = ["Yudai Takada"]
  spec.email = ["t.yudai92@gmail.com"]

  spec.summary = "High-level Ruby wrapper for Linux ptrace(2)"
  spec.description = "Ergonomic ptrace bindings for building debuggers, tracers, and strace-like tools in Ruby."
  spec.homepage = "https://github.com/ydah/ptrace-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"
  spec.platform = Gem::Platform::RUBY

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |file|
      (file == gemspec) ||
        file.start_with?(*%w[bin/ Gemfile .gitignore .rspec spec/ .github/ .idea/])
    end
  end
  spec.bindir = "bin"
  spec.executables = spec.files.grep(%r{\Abin/}) { |file| File.basename(file) }
  spec.require_paths = ["lib"]

  spec.add_dependency "fiddle", ">= 1.1"
  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "simplecov", "~> 0.22"
  spec.add_development_dependency "rubocop", "~> 1.60"
  spec.add_development_dependency "yard", "~> 0.9"
end

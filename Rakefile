# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"
require_relative "lib/rptrace/syscall_table/generator"
require "yaml"

RSpec::Core::RakeTask.new(:spec)

namespace :syscall do
  desc "Generate syscall tables from Linux headers"
  task :generate do
    arches = ENV.fetch("ARCH", "").split(",").map(&:strip).reject(&:empty?).map(&:to_sym)
    arches = Rptrace::SyscallTable::Generator::ARCH_CONFIG.keys if arches.empty?
    strict = ENV["STRICT"] == "1"

    if strict
      results = Rptrace::SyscallTable::Generator.generate_all(root_dir: __dir__, arches: arches, skip_missing: false)
      skipped = []
    else
      output = Rptrace::SyscallTable::Generator.generate_available(root_dir: __dir__, arches: arches)
      results = output.fetch(:generated)
      skipped = output.fetch(:skipped)
    end

    abort("syscall:generate failed: no headers found for requested architectures") if results.empty?

    results.each do |result|
      puts "generated #{result[:arch]} table (#{result[:entries_count]} entries)"
      puts "  header: #{result[:header_path]}"
      puts "  output: #{result[:output_path]}"
    end

    skipped.each do |entry|
      warn "skipped #{entry[:arch]}: #{entry[:reason]}"
    end
  rescue Rptrace::SyscallTable::Generator::HeaderNotFoundError, ArgumentError => e
    abort("syscall:generate failed: #{e.message}")
  end
end

namespace :release do
  desc "Run release preflight checks (unit specs, docs, gem build)"
  task :preflight do
    sh "bundle exec rspec spec/unit spec/rptrace_spec.rb"
    sh "bundle exec yard doc -n --no-cache"
    sh "gem build rptrace.gemspec"
  end

  desc "Check RubyGems API key availability for gem push"
  task :check_credentials do
    env_key = ENV["RUBYGEMS_API_KEY"]
    if env_key && !env_key.strip.empty?
      puts "RUBYGEMS_API_KEY is set in environment"
      next
    end

    credentials_path = File.expand_path("~/.gem/credentials")
    if File.readable?(credentials_path)
      credentials = YAML.load_file(credentials_path) || {}
      api_key = credentials[":rubygems_api_key"] || credentials["rubygems_api_key"]
      if api_key && !api_key.to_s.strip.empty?
        puts "RubyGems API key found in #{credentials_path}"
        next
      end
    end

    abort("release:check_credentials failed: RUBYGEMS_API_KEY is not configured")
  end
end

task default: :spec

# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"
require_relative "lib/ptrace/syscall_table/generator"

RSpec::Core::RakeTask.new(:spec)

namespace :syscall do
  desc "Generate syscall tables from Linux headers"
  task :generate do
    arches = ENV.fetch("ARCH", "").split(",").map(&:strip).reject(&:empty?).map(&:to_sym)
    arches = Ptrace::SyscallTable::Generator::ARCH_CONFIG.keys if arches.empty?
    strict = ENV["STRICT"] == "1"

    if strict
      results = Ptrace::SyscallTable::Generator.generate_all(root_dir: __dir__, arches: arches, skip_missing: false)
      skipped = []
    else
      output = Ptrace::SyscallTable::Generator.generate_available(root_dir: __dir__, arches: arches)
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
  rescue Ptrace::SyscallTable::Generator::HeaderNotFoundError, ArgumentError => e
    abort("syscall:generate failed: #{e.message}")
  end
end

task default: :spec

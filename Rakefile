# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"
require_relative "lib/ptrace/syscall_table/generator"

RSpec::Core::RakeTask.new(:spec)

namespace :syscall do
  desc "Generate syscall tables from Linux headers"
  task :generate do
    results = Ptrace::SyscallTable::Generator.generate_all(root_dir: __dir__)

    results.each do |result|
      puts "generated #{result[:arch]} table (#{result[:entries_count]} entries)"
      puts "  header: #{result[:header_path]}"
      puts "  output: #{result[:output_path]}"
    end
  rescue ArgumentError => e
    abort("syscall:generate failed: #{e.message}")
  end
end

task default: :spec

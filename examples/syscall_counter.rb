# frozen_string_literal: true

require "ptrace"

if ARGV.empty?
  warn "usage: bundle exec ruby examples/syscall_counter.rb <command> [args...]"
  exit 1
end

command = ARGV.shift
counts = Hash.new(0)

Ptrace.strace(command, *ARGV) do |event|
  next unless event.exit?

  counts[event.syscall.name] += 1
end

counts.sort_by { |(_name, count)| -count }.each do |name, count|
  puts format("%-20s %d", name, count)
end

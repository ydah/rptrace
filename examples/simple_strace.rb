# frozen_string_literal: true

require "ptrace"

if ARGV.empty?
  warn "usage: bundle exec ruby examples/simple_strace.rb <command> [args...]"
  exit 1
end

command = ARGV.shift

Ptrace.strace(command, *ARGV) do |event|
  next unless event.exit?

  puts event
end

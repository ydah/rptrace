# frozen_string_literal: true

require "rptrace"

if ARGV.empty?
  warn "usage: bundle exec ruby examples/file_access_tracer.rb <command> [args...]"
  exit 1
end

command = ARGV.shift

Rptrace.strace(command, *ARGV) do |event|
  next unless event.exit?
  next unless %i[open openat].include?(event.syscall.name)

  puts event.to_s
end

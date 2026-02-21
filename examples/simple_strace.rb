# frozen_string_literal: true

require "ptrace"

Ptrace.strace("/bin/echo", "hello") do |event|
  next unless event.exit?

  puts event
end

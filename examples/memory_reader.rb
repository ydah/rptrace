# frozen_string_literal: true

require "ptrace"

pid_str = ARGV.fetch(0) do
  warn "usage: bundle exec ruby examples/memory_reader.rb <pid>"
  exit 1
end

pid = Integer(pid_str, 10)
tracee = Ptrace::Tracee.attach(pid)

begin
  registers = tracee.registers.read
  address = case Ptrace::CStructs.arch
            when :x86_64 then registers[:rdi]
            when :aarch64 then registers[:x0]
            end

  if address.nil?
    warn "failed to determine argument register for #{Ptrace::CStructs.arch}"
    exit 1
  end

  data = tracee.memory.read_string(address, max: 128)
  puts "pid=#{pid} addr=0x#{address.to_s(16)} data=#{data.inspect}"
ensure
  tracee&.detach
end

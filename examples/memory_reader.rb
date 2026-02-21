# frozen_string_literal: true

require "ptrace"

pid_str = ARGV.fetch(0) do
  warn "usage: bundle exec ruby examples/memory_reader.rb <pid> [address_hex] [length]"
  exit 1
end

pid = Integer(pid_str, 10)
requested_address = ARGV[0] && Integer(ARGV[0], 0)
length = Integer(ARGV.fetch(1, "64"), 10)
raise ArgumentError, "length must be positive" if length <= 0

tracee = Ptrace::Tracee.attach(pid)

begin
  candidates = []
  if requested_address
    candidates << requested_address
  else
    registers = tracee.registers.read
    arch_candidates = case Ptrace::CStructs.arch
                      when :x86_64 then [registers[:rdi], registers[:rsp]]
                      when :aarch64 then [registers[:x0], registers[:sp]]
                      else []
                      end
    candidates.concat(arch_candidates.compact)
    map_candidate = tracee.memory_maps.find(&:readable?)
    candidates << map_candidate.start_addr if map_candidate
  end

  address = candidates.find do |candidate|
    tracee.memory.read(candidate, 1)
    true
  rescue Ptrace::Error
    false
  end

  unless address
    warn "failed to find readable address for pid=#{pid}"
    exit 1
  end

  data = tracee.memory.read(address, length)
  puts "pid=#{pid} addr=0x#{address.to_s(16)} bytes=#{data.unpack1('H*')} size=#{data.bytesize}"
ensure
  tracee&.detach
end

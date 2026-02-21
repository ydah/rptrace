# frozen_string_literal: true

module Ptrace
  # Renderable seccomp ptrace event.
  class SeccompEvent
    attr_reader :tracee, :syscall, :data, :metadata_flags

    # @param tracee [Ptrace::Tracee]
    # @param syscall [Ptrace::Syscall::SyscallInfo]
    # @param data [Integer]
    # @param metadata_flags [Array<Symbol>]
    def initialize(tracee:, syscall:, data:, metadata_flags: [])
      @tracee = tracee
      @syscall = syscall
      @data = Integer(data)
      @metadata_flags = Array(metadata_flags).map(&:to_sym)
    end

    # @return [String]
    def to_s
      flags = metadata_flags.empty? ? "" : " flags=#{metadata_flags.join("|")}"
      "seccomp(pid=#{tracee.pid}, syscall=#{syscall.name}, data=0x#{data.to_s(16)}#{flags})"
    end
  end
end

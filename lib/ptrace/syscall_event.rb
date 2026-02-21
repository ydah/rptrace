# frozen_string_literal: true

module Ptrace
  class SyscallEvent
    attr_reader :tracee, :syscall, :args, :return_value, :phase

    def initialize(tracee:, syscall:, args:, phase:, return_value: nil)
      @tracee = tracee
      @syscall = syscall
      @args = args
      @phase = phase
      @return_value = return_value
    end

    def enter?
      phase == :enter
    end

    def exit?
      phase == :exit
    end

    def to_s
      rendered_args = args.map { |value| value.is_a?(Integer) ? "0x#{value.to_s(16)}" : value.inspect }.join(", ")

      if exit?
        "#{syscall.name}(#{rendered_args}) = #{return_value}"
      else
        "#{syscall.name}(#{rendered_args})"
      end
    end
  end
end

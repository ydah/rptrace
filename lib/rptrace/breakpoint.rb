# frozen_string_literal: true

module Rptrace
  # Software breakpoint descriptor for a traced process.
  class Breakpoint
    attr_reader :tracee, :address, :original_byte

    # @param tracee [Rptrace::Tracee]
    # @param address [Integer]
    # @param original_byte [String] one-byte opcode before patching
    # @param enabled [Boolean]
    def initialize(tracee:, address:, original_byte:, enabled: true)
      byte = original_byte.to_s.b
      raise ArgumentError, "original_byte must be exactly one byte" unless byte.bytesize == 1

      @tracee = tracee
      @address = Integer(address)
      @original_byte = byte
      @enabled = enabled
    end

    # @return [Boolean]
    def enabled?
      @enabled
    end

    # @return [Rptrace::Breakpoint]
    def disable!
      @enabled = false
      self
    end

    # Restores original opcode through the owning tracee.
    #
    # @return [Rptrace::Breakpoint, nil]
    def restore
      tracee.remove_breakpoint(address)
    end

    # @return [String]
    def inspect
      state = enabled? ? "enabled" : "disabled"
      "#<#{self.class} addr=0x#{address.to_s(16)} state=#{state}>"
    end
  end
end

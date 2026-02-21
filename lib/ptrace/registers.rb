# frozen_string_literal: true

require "fiddle"

module Ptrace
  # Register accessor for a tracee process.
  class Registers
    def initialize(tracee, arch: CStructs.arch)
      @tracee = tracee
      @arch = arch.to_sym
    end

    # Reads all registers from kernel and returns a hash.
    #
    # @return [Hash<Symbol, Integer>]
    def read
      buffer = Fiddle::Pointer.malloc(CStructs.regs_size(arch: @arch))
      request_read(buffer)
      CStructs.decode_regs(buffer, arch: @arch)
    end

    # Updates one or more register values.
    #
    # @param values [Hash<Symbol, Integer>]
    # @return [Hash<Symbol, Integer>] merged register map
    def write(values)
      updates = normalize_updates(values)
      current = read
      merged = current.merge(updates)
      encoded = CStructs.encode_regs(merged, arch: @arch)
      buffer = Fiddle::Pointer.malloc(encoded.bytesize)
      buffer[0, encoded.bytesize] = encoded

      request_write(buffer, encoded.bytesize)
      merged
    end

    # Reads a single register value.
    #
    # @param name [Symbol, String]
    # @return [Integer]
    def [](name)
      key = normalize_reg_name(name)
      read.fetch(key)
    end

    # Writes a single register value.
    #
    # @param name [Symbol, String]
    # @param value [Integer]
    # @return [Hash<Symbol, Integer>] merged register map
    def []=(name, value)
      write(normalize_updates(name => value))
    end

    # Dynamic register getter/setter (e.g., regs.rax, regs.rax = 1).
    #
    # @param name [Symbol]
    # @param args [Array]
    # @return [Object]
    def method_missing(name, *args)
      name_str = name.to_s

      if name_str.end_with?("=")
        key = normalize_reg_name(name_str.delete_suffix("="))
        return self[key] = args.first
      end

      if register_name?(name)
        self[name]
      else
        super
      end
    end

    # @param name [Symbol, String]
    # @param include_private [Boolean]
    # @return [Boolean]
    def respond_to_missing?(name, include_private = false)
      candidate = name.to_s.delete_suffix("=")
      register_name?(candidate) || super
    end

    # @return [Hash<Symbol, Integer>]
    def to_h
      read
    end

    # @return [String]
    def inspect
      "#<#{self.class} pid=#{@tracee.pid} arch=#{@arch} regs=#{read.inspect}>"
    end

    private

    def request_read(buffer)
      if regset_mode?
        iovec = build_iovec_pointer(buffer, CStructs.regs_size(arch: @arch))
        Binding.safe_ptrace(Constants::PTRACE_GETREGSET, @tracee.pid, Constants::NT_PRSTATUS, iovec.to_i)
      else
        Binding.safe_ptrace(Constants::PTRACE_GETREGS, @tracee.pid, 0, buffer.to_i)
      end
    end

    def request_write(buffer, length)
      if regset_mode?
        iovec = build_iovec_pointer(buffer, length)
        Binding.safe_ptrace(Constants::PTRACE_SETREGSET, @tracee.pid, Constants::NT_PRSTATUS, iovec.to_i)
      else
        Binding.safe_ptrace(Constants::PTRACE_SETREGS, @tracee.pid, 0, buffer.to_i)
      end
    end

    def build_iovec_pointer(buffer, length)
      encoded = CStructs.pack_iovec(base: buffer.to_i, length: length)
      iovec = Fiddle::Pointer.malloc(encoded.bytesize)
      iovec[0, encoded.bytesize] = encoded
      iovec
    end

    def regset_mode?
      @arch == :aarch64
    end

    def register_name?(name)
      CStructs.reg_names(arch: @arch).include?(name.to_sym)
    end

    def normalize_reg_name(name)
      key = name.to_sym
      return key if register_name?(key)

      raise KeyError, "Unknown register: #{name}"
    end

    def normalize_updates(values)
      values.each_with_object({}) do |(name, value), normalized|
        key = normalize_reg_name(name)
        normalized[key] = Integer(value)
      end
    end
  end
end

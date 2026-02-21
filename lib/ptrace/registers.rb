# frozen_string_literal: true

require "fiddle"

module Ptrace
  class Registers
    def initialize(tracee)
      @tracee = tracee
    end

    def read
      buffer = Fiddle::Pointer.malloc(CStructs.regs_size)
      Binding.safe_ptrace(Constants::PTRACE_GETREGS, @tracee.pid, 0, buffer.to_i)
      CStructs.decode_regs(buffer)
    end

    def write(values)
      updates = normalize_updates(values)
      current = read
      merged = current.merge(updates)
      encoded = CStructs.encode_regs(merged)
      buffer = Fiddle::Pointer.malloc(encoded.bytesize)
      buffer[0, encoded.bytesize] = encoded

      Binding.safe_ptrace(Constants::PTRACE_SETREGS, @tracee.pid, 0, buffer.to_i)
      merged
    end

    def [](name)
      key = normalize_reg_name(name)
      read.fetch(key)
    end

    def []=(name, value)
      write(normalize_updates(name => value))
    end

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

    def respond_to_missing?(name, include_private = false)
      candidate = name.to_s.delete_suffix("=")
      register_name?(candidate) || super
    end

    def to_h
      read
    end

    def inspect
      "#<#{self.class} pid=#{@tracee.pid} regs=#{read.inspect}>"
    end

    private

    def register_name?(name)
      CStructs.reg_names.include?(name.to_sym)
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

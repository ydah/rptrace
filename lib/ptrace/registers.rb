# frozen_string_literal: true

module Ptrace
  class Registers
    def initialize(tracee)
      @tracee = tracee
    end

    def read
      raise NotImplementedError, "Registers#read is not implemented yet"
    end

    def write(_hash)
      raise NotImplementedError, "Registers#write is not implemented yet"
    end

    def [](name)
      read.fetch(name.to_sym)
    end

    def []=(name, value)
      current = read
      current[name.to_sym] = value
      write(current)
    end

    def method_missing(name, *args)
      name_str = name.to_s

      if name_str.end_with?("=")
        self[name_str.delete_suffix("=")] = args.first
      else
        self[name]
      end
    end

    def respond_to_missing?(_name, _include_private = false)
      true
    end
  end
end

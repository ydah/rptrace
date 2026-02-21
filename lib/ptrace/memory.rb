# frozen_string_literal: true

module Ptrace
  class Memory
    WORD_SIZE = begin
      [0].pack("J").bytesize
    rescue StandardError
      8
    end

    def initialize(tracee)
      @tracee = tracee
    end

    def read(_addr, _length)
      raise NotImplementedError, "Memory#read is not implemented yet"
    end

    def write(_addr, _bytes)
      raise NotImplementedError, "Memory#write is not implemented yet"
    end

    def read_string(_addr, max: 4096)
      raise NotImplementedError, "Memory#read_string is not implemented yet"
    end

    def [](addr)
      read(addr, WORD_SIZE)
    end

    def []=(addr, value)
      pack_format = WORD_SIZE == 8 ? "Q<" : "L<"
      write(addr, [Integer(value)].pack(pack_format))
    end
  end
end

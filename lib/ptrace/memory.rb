# frozen_string_literal: true

module Ptrace
  # Memory accessor for traced process address space.
  class Memory
    WORD_SIZE = begin
      [0].pack("J").bytesize
    rescue StandardError
      8
    end

    def initialize(tracee)
      @tracee = tracee
    end

    # Reads bytes from tracee memory.
    #
    # @param addr [Integer] start address
    # @param length [Integer] byte length
    # @return [String] binary string
    def read(addr, length)
      address = Integer(addr)
      size = Integer(length)
      raise ArgumentError, "length must be non-negative" if size.negative?
      return "".b if size.zero?

      aligned_start = align_down(address)
      aligned_end = align_up(address + size)
      buffer = +"".b

      aligned_start.step(aligned_end - WORD_SIZE, WORD_SIZE) do |word_addr|
        buffer << pack_word(read_word(word_addr))
      end

      offset = address - aligned_start
      buffer.byteslice(offset, size)
    end

    # Writes bytes into tracee memory.
    #
    # @param addr [Integer] start address
    # @param bytes [String] binary/string data
    # @return [Integer] written byte length
    def write(addr, bytes)
      address = Integer(addr)
      data = bytes.to_s.b
      return 0 if data.empty?

      aligned_start = align_down(address)
      aligned_end = align_up(address + data.bytesize)

      aligned_start.step(aligned_end - WORD_SIZE, WORD_SIZE) do |word_addr|
        updated_word = if full_word_write?(word_addr, address, data.bytesize)
                         word_offset = word_addr - address
                         unpack_word(data.byteslice(word_offset, WORD_SIZE))
                       else
                         merge_word(word_addr, address, data)
                       end

        write_word(word_addr, updated_word)
      end

      data.bytesize
    end

    # Reads a NUL-terminated string from tracee memory.
    #
    # @param addr [Integer] start address
    # @param max [Integer] max bytes to scan
    # @return [String] decoded bytes up to NUL or max
    def read_string(addr, max: 4096)
      limit = Integer(max)
      raise ArgumentError, "max must be positive" if limit <= 0

      read_bytes = read(addr, limit)
      nul_index = read_bytes.index("\x00")
      return read_bytes.byteslice(0, nul_index) if nul_index

      read_bytes
    end

    def [](addr)
      read(addr, WORD_SIZE)
    end

    def []=(addr, value)
      pack_format = WORD_SIZE == 8 ? "Q<" : "L<"
      write(addr, [Integer(value)].pack(pack_format))
    end

    private

    def align_down(address)
      address - (address % WORD_SIZE)
    end

    def align_up(address)
      remainder = address % WORD_SIZE
      return address if remainder.zero?

      address + (WORD_SIZE - remainder)
    end

    def full_word_write?(word_addr, start_addr, data_size)
      word_addr >= start_addr && (word_addr + WORD_SIZE) <= (start_addr + data_size)
    end

    def merge_word(word_addr, start_addr, data)
      current = pack_word(read_word(word_addr))
      from = [word_addr, start_addr].max
      to = [word_addr + WORD_SIZE, start_addr + data.bytesize].min

      from.upto(to - 1) do |absolute_addr|
        src_index = absolute_addr - start_addr
        dst_index = absolute_addr - word_addr
        current.setbyte(dst_index, data.getbyte(src_index))
      end

      unpack_word(current)
    end

    def read_word(addr)
      Binding.safe_ptrace(Constants::PTRACE_PEEKDATA, @tracee.pid, addr, 0)
    end

    def write_word(addr, value)
      Binding.safe_ptrace(Constants::PTRACE_POKEDATA, @tracee.pid, addr, value)
    end

    def word_mask
      @word_mask ||= (1 << (WORD_SIZE * 8)) - 1
    end

    def pack_word(value)
      format = WORD_SIZE == 8 ? "Q<" : "L<"
      [Integer(value) & word_mask].pack(format)
    end

    def unpack_word(bytes)
      format = WORD_SIZE == 8 ? "Q<" : "L<"
      bytes.unpack1(format)
    end
  end
end

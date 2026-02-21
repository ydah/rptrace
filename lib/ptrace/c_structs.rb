# frozen_string_literal: true

require "rbconfig"

module Ptrace
  module CStructs
    POINTER_SIZE = begin
      [0].pack("J").bytesize
    rescue StandardError
      8
    end
    POINTER_PACK = POINTER_SIZE == 8 ? "Q<" : "L<"
    WORD_SIZE = 8
    WORD_MASK = (1 << (WORD_SIZE * 8)) - 1
    PACK_FORMAT = "Q<"

    X86_64_REGS = %i[
      r15 r14 r13 r12 rbp rbx r11 r10 r9 r8
      rax rcx rdx rsi rdi orig_rax rip cs eflags
      rsp ss fs_base gs_base ds es fs gs
    ].freeze

    AARCH64_REGS = (0..30).map { |i| :"x#{i}" }.push(:sp, :pc, :pstate).freeze

    module_function

    def arch
      @arch ||= detect_arch
    end

    def reg_names(arch: self.arch)
      case arch
      when :x86_64 then X86_64_REGS
      when :aarch64 then AARCH64_REGS
      else
        raise UnsupportedArchError, "Unsupported architecture: #{arch}"
      end
    end

    def regs_size(arch: self.arch)
      reg_names(arch: arch).size * 8
    end

    def decode_regs(source, arch: self.arch)
      bytes = source.is_a?(String) ? source : source[0, regs_size(arch: arch)]
      values = bytes.unpack("#{PACK_FORMAT}*")
      names = reg_names(arch: arch)

      names.each_with_index.each_with_object({}) do |(name, index), decoded|
        decoded[name] = values.fetch(index, 0)
      end
    end

    def encode_regs(regs, arch: self.arch)
      names = reg_names(arch: arch)
      values = names.map { |name| Integer(regs.fetch(name, 0)) & WORD_MASK }
      values.pack("#{PACK_FORMAT}*")
    end

    def pack_iovec(base:, length:)
      [Integer(base), Integer(length)].pack("#{POINTER_PACK}#{POINTER_PACK}")
    end

    def unpack_iovec(bytes)
      base, length = bytes.unpack("#{POINTER_PACK}#{POINTER_PACK}")
      { base: base, length: length }
    end

    def detect_arch
      host_cpu = RbConfig::CONFIG.fetch("host_cpu", "")

      case host_cpu
      when /x86_64|amd64/
        :x86_64
      when /aarch64|arm64/
        :aarch64
      else
        raise UnsupportedArchError, "Unsupported architecture: #{host_cpu}"
      end
    end
  end
end

# frozen_string_literal: true

require "rbconfig"

module Ptrace
  # Architecture-specific register layouts and binary helpers.
  module CStructs
    # Host pointer width in bytes.
    POINTER_SIZE = begin
      [0].pack("J").bytesize
    rescue StandardError
      8
    end
    # Pointer pack format for host pointer size.
    POINTER_PACK = POINTER_SIZE == 8 ? "Q<" : "L<"
    # Register word width in bytes.
    WORD_SIZE = 8
    # Register word bitmask.
    WORD_MASK = (1 << (WORD_SIZE * 8)) - 1
    # Register word unpack/pack format.
    PACK_FORMAT = "Q<"
    # seccomp metadata struct pack format.
    SECCOMP_METADATA_FORMAT = "Q<Q<"
    # seccomp metadata struct size.
    SECCOMP_METADATA_SIZE = 16
    # BPF instruction size in seccomp filter dump.
    SECCOMP_FILTER_INSN_SIZE = 8

    # x86_64 user_regs_struct register names.
    X86_64_REGS = %i[
      r15 r14 r13 r12 rbp rbx r11 r10 r9 r8
      rax rcx rdx rsi rdi orig_rax rip cs eflags
      rsp ss fs_base gs_base ds es fs gs
    ].freeze

    # aarch64 register names returned by NT_PRSTATUS regset.
    AARCH64_REGS = (0..30).map { |i| :"x#{i}" }.push(:sp, :pc, :pstate).freeze

    module_function

    # @return [Symbol] :x86_64 or :aarch64
    def arch
      @arch ||= detect_arch
    end

    # @param arch [Symbol]
    # @return [Array<Symbol>]
    def reg_names(arch: self.arch)
      case arch
      when :x86_64 then X86_64_REGS
      when :aarch64 then AARCH64_REGS
      else
        raise UnsupportedArchError, "Unsupported architecture: #{arch}"
      end
    end

    # @param arch [Symbol]
    # @return [Integer]
    def regs_size(arch: self.arch)
      reg_names(arch: arch).size * 8
    end

    # @param source [String, Fiddle::Pointer]
    # @param arch [Symbol]
    # @return [Hash<Symbol, Integer>]
    def decode_regs(source, arch: self.arch)
      bytes = source.is_a?(String) ? source : source[0, regs_size(arch: arch)]
      values = bytes.unpack("#{PACK_FORMAT}*")
      names = reg_names(arch: arch)

      names.each_with_index.each_with_object({}) do |(name, index), decoded|
        decoded[name] = values.fetch(index, 0)
      end
    end

    # @param regs [Hash<Symbol, Integer>]
    # @param arch [Symbol]
    # @return [String] packed binary register bytes
    def encode_regs(regs, arch: self.arch)
      names = reg_names(arch: arch)
      values = names.map { |name| Integer(regs.fetch(name, 0)) & WORD_MASK }
      values.pack("#{PACK_FORMAT}*")
    end

    # @param base [Integer]
    # @param length [Integer]
    # @return [String] packed iovec
    def pack_iovec(base:, length:)
      [Integer(base), Integer(length)].pack("#{POINTER_PACK}#{POINTER_PACK}")
    end

    # @param bytes [String]
    # @return [Hash<Symbol, Integer>]
    def unpack_iovec(bytes)
      base, length = bytes.unpack("#{POINTER_PACK}#{POINTER_PACK}")
      { base: base, length: length }
    end

    # @return [Integer]
    def seccomp_metadata_size
      SECCOMP_METADATA_SIZE
    end

    # @param filter_off [Integer]
    # @param flags [Integer]
    # @return [String]
    def pack_seccomp_metadata(filter_off:, flags: 0)
      [Integer(filter_off), Integer(flags)].pack(SECCOMP_METADATA_FORMAT)
    end

    # @param bytes [String]
    # @return [Hash<Symbol, Integer>]
    def unpack_seccomp_metadata(bytes)
      filter_off, flags = bytes.unpack(SECCOMP_METADATA_FORMAT)
      { filter_off: filter_off, flags: flags }
    end

    # @param bytes [String]
    # @return [Array<Hash<Symbol, Integer>>]
    def decode_seccomp_filter(bytes)
      blob = bytes.to_s.b
      raise ArgumentError, "seccomp filter bytes must align to #{SECCOMP_FILTER_INSN_SIZE}" unless (blob.bytesize % SECCOMP_FILTER_INSN_SIZE).zero?

      instructions = []
      blob.bytes.each_slice(SECCOMP_FILTER_INSN_SIZE) do |insn|
        code, jt, jf, k = insn.pack("C*").unpack("S<CCL<")
        instructions << { code: code, jt: jt, jf: jf, k: k }
      end
      instructions
    end

    # @return [Symbol]
    # @raise [Ptrace::UnsupportedArchError]
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

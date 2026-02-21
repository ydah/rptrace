# frozen_string_literal: true

require "rbconfig"

module Ptrace
  module CStructs
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

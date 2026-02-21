# frozen_string_literal: true

module Ptrace
  module Syscall
    SyscallInfo = Struct.new(:number, :name, :arg_names, :arg_types, keyword_init: true)

    ARG_TYPES = %i[int uint fd ptr str buf size flags mode pid].freeze

    require_relative "syscall_table/x86_64"
    require_relative "syscall_table/aarch64"

    module_function

    def from_number(number, arch: CStructs.arch)
      number = Integer(number)
      table(arch: arch).fetch(number) do
        SyscallInfo.new(number: number, name: :"syscall_#{number}", arg_names: [], arg_types: [])
      end
    end

    def from_name(name, arch: CStructs.arch)
      sym = name.to_sym
      by_name_table(arch: arch)[sym]
    end

    def table(arch: CStructs.arch)
      case arch
      when :x86_64 then SyscallTable::X86_64::TABLE
      when :aarch64 then SyscallTable::AARCH64::TABLE
      else
        {}
      end
    end

    def by_name_table(arch: CStructs.arch)
      case arch
      when :x86_64 then SyscallTable::X86_64::BY_NAME
      when :aarch64 then SyscallTable::AARCH64::BY_NAME
      else
        {}
      end
    end
  end
end

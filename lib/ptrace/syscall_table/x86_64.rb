# frozen_string_literal: true

module Ptrace
  module SyscallTable
    module X86_64
      TABLE = {
        0 => Syscall::SyscallInfo.new(number: 0, name: :read, arg_names: %i[fd buf count], arg_types: %i[fd buf size]),
        1 => Syscall::SyscallInfo.new(number: 1, name: :write, arg_names: %i[fd buf count], arg_types: %i[fd buf size]),
        2 => Syscall::SyscallInfo.new(number: 2, name: :open, arg_names: %i[path flags mode], arg_types: %i[str flags mode]),
        3 => Syscall::SyscallInfo.new(number: 3, name: :close, arg_names: %i[fd], arg_types: %i[fd]),
        59 => Syscall::SyscallInfo.new(number: 59, name: :execve, arg_names: %i[filename argv envp], arg_types: %i[str ptr ptr]),
        60 => Syscall::SyscallInfo.new(number: 60, name: :exit, arg_names: %i[status], arg_types: %i[int]),
        231 => Syscall::SyscallInfo.new(number: 231, name: :exit_group, arg_names: %i[status], arg_types: %i[int]),
        257 => Syscall::SyscallInfo.new(number: 257, name: :openat, arg_names: %i[dirfd pathname flags mode], arg_types: %i[fd str flags mode])
      }.freeze

      BY_NAME = TABLE.each_with_object({}) do |(_number, info), map|
        map[info.name] = info
      end.freeze
    end
  end
end

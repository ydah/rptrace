# frozen_string_literal: true

module Ptrace
  module SyscallTable
    module AARCH64
      TABLE = {
        56 => Syscall::SyscallInfo.new(number: 56, name: :openat, arg_names: %i[dirfd pathname flags mode], arg_types: %i[fd str flags mode]),
        57 => Syscall::SyscallInfo.new(number: 57, name: :close, arg_names: %i[fd], arg_types: %i[fd]),
        63 => Syscall::SyscallInfo.new(number: 63, name: :read, arg_names: %i[fd buf count], arg_types: %i[fd buf size]),
        64 => Syscall::SyscallInfo.new(number: 64, name: :write, arg_names: %i[fd buf count], arg_types: %i[fd buf size]),
        93 => Syscall::SyscallInfo.new(number: 93, name: :exit, arg_names: %i[status], arg_types: %i[int]),
        94 => Syscall::SyscallInfo.new(number: 94, name: :exit_group, arg_names: %i[status], arg_types: %i[int]),
        221 => Syscall::SyscallInfo.new(number: 221, name: :execve, arg_names: %i[filename argv envp], arg_types: %i[str ptr ptr])
      }.freeze

      BY_NAME = TABLE.each_with_object({}) do |(_number, info), map|
        map[info.name] = info
      end.freeze
    end
  end
end

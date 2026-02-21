# frozen_string_literal: true

module Rptrace
  # Built-in syscall number table modules.
  module SyscallTable
    # x86_64 syscall table.
    module X86_64
      # @return [Hash{Integer => Rptrace::Syscall::SyscallInfo}]
      TABLE = {
        0 => Syscall::SyscallInfo.new(number: 0, name: :read, arg_names: [], arg_types: []),
        1 => Syscall::SyscallInfo.new(number: 1, name: :write, arg_names: [], arg_types: []),
        2 => Syscall::SyscallInfo.new(number: 2, name: :open, arg_names: [], arg_types: []),
        3 => Syscall::SyscallInfo.new(number: 3, name: :close, arg_names: [], arg_types: []),
        4 => Syscall::SyscallInfo.new(number: 4, name: :stat, arg_names: [], arg_types: []),
        5 => Syscall::SyscallInfo.new(number: 5, name: :fstat, arg_names: [], arg_types: []),
        6 => Syscall::SyscallInfo.new(number: 6, name: :lstat, arg_names: [], arg_types: []),
        7 => Syscall::SyscallInfo.new(number: 7, name: :poll, arg_names: [], arg_types: []),
        8 => Syscall::SyscallInfo.new(number: 8, name: :lseek, arg_names: [], arg_types: []),
        9 => Syscall::SyscallInfo.new(number: 9, name: :mmap, arg_names: [], arg_types: []),
        10 => Syscall::SyscallInfo.new(number: 10, name: :mprotect, arg_names: [], arg_types: []),
        11 => Syscall::SyscallInfo.new(number: 11, name: :munmap, arg_names: [], arg_types: []),
        12 => Syscall::SyscallInfo.new(number: 12, name: :brk, arg_names: [], arg_types: []),
        16 => Syscall::SyscallInfo.new(number: 16, name: :ioctl, arg_names: [], arg_types: []),
        21 => Syscall::SyscallInfo.new(number: 21, name: :access, arg_names: [], arg_types: []),
        22 => Syscall::SyscallInfo.new(number: 22, name: :pipe, arg_names: [], arg_types: []),
        23 => Syscall::SyscallInfo.new(number: 23, name: :select, arg_names: [], arg_types: []),
        32 => Syscall::SyscallInfo.new(number: 32, name: :dup, arg_names: [], arg_types: []),
        33 => Syscall::SyscallInfo.new(number: 33, name: :dup2, arg_names: [], arg_types: []),
        41 => Syscall::SyscallInfo.new(number: 41, name: :socket, arg_names: [], arg_types: []),
        42 => Syscall::SyscallInfo.new(number: 42, name: :connect, arg_names: [], arg_types: []),
        43 => Syscall::SyscallInfo.new(number: 43, name: :accept, arg_names: [], arg_types: []),
        44 => Syscall::SyscallInfo.new(number: 44, name: :sendto, arg_names: [], arg_types: []),
        45 => Syscall::SyscallInfo.new(number: 45, name: :recvfrom, arg_names: [], arg_types: []),
        48 => Syscall::SyscallInfo.new(number: 48, name: :shutdown, arg_names: [], arg_types: []),
        49 => Syscall::SyscallInfo.new(number: 49, name: :bind, arg_names: [], arg_types: []),
        50 => Syscall::SyscallInfo.new(number: 50, name: :listen, arg_names: [], arg_types: []),
        56 => Syscall::SyscallInfo.new(number: 56, name: :clone, arg_names: [], arg_types: []),
        57 => Syscall::SyscallInfo.new(number: 57, name: :fork, arg_names: [], arg_types: []),
        58 => Syscall::SyscallInfo.new(number: 58, name: :vfork, arg_names: [], arg_types: []),
        59 => Syscall::SyscallInfo.new(number: 59, name: :execve, arg_names: [], arg_types: []),
        60 => Syscall::SyscallInfo.new(number: 60, name: :exit, arg_names: [], arg_types: []),
        61 => Syscall::SyscallInfo.new(number: 61, name: :wait4, arg_names: [], arg_types: []),
        62 => Syscall::SyscallInfo.new(number: 62, name: :kill, arg_names: [], arg_types: []),
        72 => Syscall::SyscallInfo.new(number: 72, name: :fcntl, arg_names: [], arg_types: []),
        73 => Syscall::SyscallInfo.new(number: 73, name: :flock, arg_names: [], arg_types: []),
        74 => Syscall::SyscallInfo.new(number: 74, name: :fsync, arg_names: [], arg_types: []),
        231 => Syscall::SyscallInfo.new(number: 231, name: :exit_group, arg_names: [], arg_types: []),
        257 => Syscall::SyscallInfo.new(number: 257, name: :openat, arg_names: [], arg_types: []),
        262 => Syscall::SyscallInfo.new(number: 262, name: :newfstatat, arg_names: [], arg_types: []),
        267 => Syscall::SyscallInfo.new(number: 267, name: :readlinkat, arg_names: [], arg_types: []),
        269 => Syscall::SyscallInfo.new(number: 269, name: :faccessat, arg_names: [], arg_types: [])
      }.freeze

      # @return [Hash{Symbol => Rptrace::Syscall::SyscallInfo}]
      BY_NAME = TABLE.each_with_object({}) do |(_number, info), map|
        map[info.name] = info
      end.freeze
    end
  end
end

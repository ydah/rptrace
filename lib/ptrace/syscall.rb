# frozen_string_literal: true

module Ptrace
  # Syscall metadata lookup and argument templates.
  module Syscall
    SyscallInfo = Struct.new(:number, :name, :arg_names, :arg_types, keyword_init: true)

    ARG_TYPES = %i[int uint fd ptr str buf size flags mode pid].freeze
    SYSCALL_TEMPLATES = {
      read: [%i[fd buf count], %i[fd buf size]],
      write: [%i[fd buf count], %i[fd buf size]],
      open: [%i[pathname flags mode], %i[str flags mode]],
      close: [%i[fd], %i[fd]],
      stat: [%i[pathname statbuf], %i[str ptr]],
      fstat: [%i[fd statbuf], %i[fd ptr]],
      lstat: [%i[pathname statbuf], %i[str ptr]],
      poll: [%i[fds nfds timeout], %i[ptr uint int]],
      lseek: [%i[fd offset whence], %i[fd int int]],
      mmap: [%i[addr length prot flags fd offset], %i[ptr size flags flags fd int]],
      mprotect: [%i[addr len prot], %i[ptr size flags]],
      munmap: [%i[addr len], %i[ptr size]],
      brk: [%i[addr], %i[ptr]],
      ioctl: [%i[fd request argp], %i[fd uint ptr]],
      access: [%i[pathname mode], %i[str mode]],
      pipe: [%i[pipefd], %i[ptr]],
      select: [%i[nfds readfds writefds exceptfds timeout], %i[int ptr ptr ptr ptr]],
      dup: [%i[oldfd], %i[fd]],
      dup2: [%i[oldfd newfd], %i[fd fd]],
      clone: [%i[flags child_stack ptid ctid newtls], %i[flags ptr ptr ptr ptr]],
      fork: [[], []],
      vfork: [[], []],
      execve: [%i[filename argv envp], %i[str ptr ptr]],
      exit: [%i[status], %i[int]],
      exit_group: [%i[status], %i[int]],
      wait4: [%i[pid stat_addr options rusage], %i[pid ptr flags ptr]],
      kill: [%i[pid sig], %i[pid int]],
      fcntl: [%i[fd cmd arg], %i[fd int ptr]],
      flock: [%i[fd operation], %i[fd flags]],
      fsync: [%i[fd], %i[fd]],
      sendto: [%i[sockfd buf len flags dest_addr addrlen], %i[fd buf size flags ptr uint]],
      recvfrom: [%i[sockfd buf len flags src_addr addrlen], %i[fd buf size flags ptr ptr]],
      socket: [%i[domain type protocol], %i[int int int]],
      connect: [%i[sockfd addr addrlen], %i[fd ptr uint]],
      accept: [%i[sockfd addr addrlen], %i[fd ptr ptr]],
      bind: [%i[sockfd addr addrlen], %i[fd ptr uint]],
      listen: [%i[sockfd backlog], %i[fd int]],
      shutdown: [%i[sockfd how], %i[fd int]],
      openat: [%i[dirfd pathname flags mode], %i[fd str flags mode]],
      readlinkat: [%i[dirfd pathname buf bufsiz], %i[fd str buf size]],
      faccessat: [%i[dirfd pathname mode], %i[fd str mode]],
      newfstatat: [%i[dirfd pathname statbuf flags], %i[fd str ptr flags]]
    }.freeze

    require_relative "syscall_table/x86_64"
    require_relative "syscall_table/aarch64"

    module_function

    # @param number [Integer]
    # @param arch [Symbol]
    # @return [SyscallInfo]
    def from_number(number, arch: CStructs.arch)
      number = Integer(number)
      info = table(arch: arch).fetch(number) do
        SyscallInfo.new(number: number, name: :"syscall_#{number}", arg_names: [], arg_types: [])
      end
      apply_template(info)
    end

    # @param name [Symbol, String]
    # @param arch [Symbol]
    # @return [SyscallInfo, nil]
    def from_name(name, arch: CStructs.arch)
      sym = name.to_sym
      info = by_name_table(arch: arch)[sym]
      return nil unless info

      apply_template(info)
    end

    # @param arch [Symbol]
    # @return [Hash{Integer => SyscallInfo}]
    def table(arch: CStructs.arch)
      case arch
      when :x86_64 then SyscallTable::X86_64::TABLE
      when :aarch64 then SyscallTable::AARCH64::TABLE
      else
        {}
      end
    end

    # @param arch [Symbol]
    # @return [Hash{Symbol => SyscallInfo}]
    def by_name_table(arch: CStructs.arch)
      case arch
      when :x86_64 then SyscallTable::X86_64::BY_NAME
      when :aarch64 then SyscallTable::AARCH64::BY_NAME
      else
        {}
      end
    end

    def apply_template(info)
      template = SYSCALL_TEMPLATES[info.name]
      return info unless template

      arg_names, arg_types = template
      SyscallInfo.new(number: info.number, name: info.name, arg_names: arg_names, arg_types: arg_types)
    end
    private_class_method :apply_template
  end
end

# frozen_string_literal: true

require "fiddle"
require "fiddle/import"

module Ptrace
  # Low-level libc bindings for ptrace and waitpid.
  module Binding
    extend Fiddle::Importer
    include Constants

    dlload Fiddle::Handle::DEFAULT

    extern "long ptrace(int, int, unsigned long, unsigned long)"
    extern "int waitpid(int, void*, int)"
    extern "int fork()"
    extern "int execvp(char*, void*)"

    # Maps errno values to specific Ptrace error subclasses.
    ERRNO_CLASS_MAP = {
      Errno::EPERM::Errno => PermissionError,
      Errno::ESRCH::Errno => NoProcessError,
      Errno::EBUSY::Errno => BusyError,
      Errno::EINVAL::Errno => InvalidArgError
    }.freeze
    PERMISSION_HINT = "try running as root, granting CAP_SYS_PTRACE, and checking /proc/sys/kernel/yama/ptrace_scope".freeze

    class << self
      # Calls ptrace and raises mapped Ptrace::Error subclasses on failure.
      #
      # @param request [Integer, Symbol]
      # @param pid [Integer]
      # @param addr [Integer]
      # @param data [Integer]
      # @return [Integer]
      def safe_ptrace(request, pid, addr, data)
        clear_errno!
        result = ptrace(request, pid, addr, data)
        errno = Fiddle.last_error
        return result unless result == -1 && errno.positive?

        raise_ptrace_error(errno, request)
      end

      # Calls waitpid and decodes raw status.
      #
      # @param pid [Integer]
      # @param flags [Integer]
      # @return [Array<(Integer, Integer)>] waited pid and raw status
      def safe_waitpid(pid, flags: 0)
        status_ptr = Fiddle::Pointer.malloc(Fiddle::SIZEOF_INT)

        clear_errno!
        waited_pid = waitpid(pid, status_ptr, flags)
        errno = Fiddle.last_error

        raise_ptrace_error(errno, :waitpid) if waited_pid == -1

        status = status_ptr[0, Fiddle::SIZEOF_INT].unpack1("i")
        [waited_pid, status]
      end

      # Resets thread-local errno to zero.
      #
      # @return [Integer]
      def clear_errno!
        Fiddle.last_error = 0
      end

      # Raises a mapped Ptrace::Error subclass for an errno code.
      #
      # @param errno [Integer]
      # @param request [Integer, Symbol]
      # @raise [Ptrace::Error]
      # @return [void]
      def raise_ptrace_error(errno, request)
        klass = ERRNO_CLASS_MAP.fetch(errno, Error)
        message = SystemCallError.new("ptrace", errno).message
        message = "#{message}; #{PERMISSION_HINT}" if klass == PermissionError
        raise klass.new(message, errno: errno, request: request)
      end
    end
  end
end

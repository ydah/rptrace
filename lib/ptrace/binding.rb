# frozen_string_literal: true

require "fiddle"
require "fiddle/import"

module Ptrace
  module Binding
    extend Fiddle::Importer
    include Constants

    dlload Fiddle::Handle::DEFAULT

    extern "long ptrace(int, int, unsigned long, unsigned long)"
    extern "int waitpid(int, void*, int)"
    extern "int fork()"
    extern "int execvp(char*, void*)"

    ERRNO_CLASS_MAP = {
      Errno::EPERM::Errno => PermissionError,
      Errno::ESRCH::Errno => NoProcessError,
      Errno::EBUSY::Errno => BusyError,
      Errno::EINVAL::Errno => InvalidArgError
    }.freeze

    class << self
      def safe_ptrace(request, pid, addr, data)
        clear_errno!
        result = ptrace(request, pid, addr, data)
        errno = Fiddle.last_error
        return result unless result == -1 && errno.positive?

        raise_ptrace_error(errno, request)
      end

      def safe_waitpid(pid, flags: 0)
        status_ptr = Fiddle::Pointer.malloc(Fiddle::SIZEOF_INT)

        clear_errno!
        waited_pid = waitpid(pid, status_ptr, flags)
        errno = Fiddle.last_error

        raise_ptrace_error(errno, :waitpid) if waited_pid == -1

        status = status_ptr[0, Fiddle::SIZEOF_INT].unpack1("i")
        [waited_pid, status]
      end

      def clear_errno!
        Fiddle.last_error = 0
      end

      def raise_ptrace_error(errno, request)
        klass = ERRNO_CLASS_MAP.fetch(errno, Error)
        message = SystemCallError.new("ptrace", errno).message
        raise klass.new(message, errno: errno, request: request)
      end
    end
  end
end

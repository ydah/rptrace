# frozen_string_literal: true

module Ptrace
  # Base error for ptrace operations.
  class Error < StandardError
    attr_reader :errno, :request

    def initialize(message = nil, errno: nil, request: nil)
      @errno = errno
      @request = request

      if errno && request
        super("ptrace(#{request}): #{message} (errno=#{errno})")
      else
        super(message)
      end
    end
  end

  # Error raised for EPERM.
  class PermissionError < Error; end
  # Error raised for ESRCH.
  class NoProcessError < Error; end
  # Error raised for EBUSY.
  class BusyError < Error; end
  # Error raised for EINVAL.
  class InvalidArgError < Error; end
  # Unsupported architecture error.
  class UnsupportedArchError < StandardError; end
end

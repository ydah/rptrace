# frozen_string_literal: true

module Ptrace
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

  class PermissionError < Error; end
  class NoProcessError < Error; end
  class BusyError < Error; end
  class InvalidArgError < Error; end
  class UnsupportedArchError < StandardError; end
end

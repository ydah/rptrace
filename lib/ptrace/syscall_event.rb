# frozen_string_literal: true

module Ptrace
  class SyscallEvent
    ERRNO_NAME_BY_NUMBER = Errno.constants.each_with_object({}) do |const_name, map|
      errno_class = Errno.const_get(const_name)
      next unless errno_class.is_a?(Class) && errno_class < SystemCallError
      next unless errno_class.const_defined?(:Errno)

      map[errno_class::Errno] ||= const_name.to_s
    rescue NameError
      next
    end.freeze
    LINUX_MAX_ERRNO = 4095

    attr_reader :tracee, :syscall, :args, :return_value, :phase

    def initialize(tracee:, syscall:, args:, phase:, return_value: nil)
      @tracee = tracee
      @syscall = syscall
      @args = args
      @phase = phase
      @return_value = return_value
    end

    def enter?
      phase == :enter
    end

    def exit?
      phase == :exit
    end

    def to_s
      call = "#{syscall.name}(#{formatted_args})"
      return "#{call} ..." if enter?

      "#{call} = #{formatted_return_value}"
    end

    def formatted_args
      args.each_with_index.map do |value, index|
        type = syscall.arg_types.fetch(index, nil)
        format_argument(type, value)
      end.join(", ")
    end

    def formatted_return_value
      return "?" if return_value.nil?
      return return_value.to_s unless syscall_error_code?(return_value)

      errno = -return_value
      name = ERRNO_NAME_BY_NUMBER.fetch(errno, "ERRNO_#{errno}")
      message = SystemCallError.new(errno).message
      "-1 #{name} (#{message})"
    end

    private

    def format_argument(type, value)
      case type
      when :str
        format_string_pointer(value)
      when :ptr, :buf
        format_pointer(value)
      when :flags
        format("0x%x", Integer(value))
      when :fd, :int, :uint, :size, :mode, :pid
        Integer(value).to_s
      else
        value.inspect
      end
    end

    def format_string_pointer(value)
      return "NULL" if pointer_null?(value)

      tracee.memory.read_string(Integer(value)).inspect
    rescue Ptrace::Error, StandardError
      format_pointer(value)
    end

    def format_pointer(value)
      return "NULL" if pointer_null?(value)

      format("0x%x", Integer(value))
    end

    def pointer_null?(value)
      Integer(value).zero?
    rescue StandardError
      false
    end

    def syscall_error_code?(value)
      value.is_a?(Integer) && value.negative? && (-value) <= LINUX_MAX_ERRNO
    end
  end
end

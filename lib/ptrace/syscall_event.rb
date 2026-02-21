# frozen_string_literal: true

require "fcntl"

module Ptrace
  # Renderable syscall event (enter/exit).
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
    OPEN_ACCESS_MASK = Fcntl.const_defined?(:O_ACCMODE) ? Fcntl::O_ACCMODE : 0x3
    OPEN_ACCESS_NAMES = {
      (Fcntl.const_defined?(:O_RDONLY) ? Fcntl::O_RDONLY : 0) => "O_RDONLY",
      (Fcntl.const_defined?(:O_WRONLY) ? Fcntl::O_WRONLY : 1) => "O_WRONLY",
      (Fcntl.const_defined?(:O_RDWR) ? Fcntl::O_RDWR : 2) => "O_RDWR"
    }.freeze
    OPEN_FLAG_NAMES = %i[
      O_APPEND O_ASYNC O_CLOEXEC O_CREAT O_DIRECT O_DIRECTORY O_DSYNC O_EXCL O_LARGEFILE
      O_NOATIME O_NOCTTY O_NOFOLLOW O_NONBLOCK O_PATH O_SYNC O_TMPFILE O_TRUNC
    ].each_with_object({}) do |const_name, map|
      next unless Fcntl.const_defined?(const_name)

      value = Fcntl.const_get(const_name)
      next unless value.is_a?(Integer) && value.positive?

      map[value] = const_name.to_s
    end.freeze

    attr_reader :tracee, :syscall, :args, :return_value, :phase

    def initialize(tracee:, syscall:, args:, phase:, return_value: nil)
      @tracee = tracee
      @syscall = syscall
      @args = args
      @phase = phase
      @return_value = return_value
    end

    # @return [Boolean]
    def enter?
      phase == :enter
    end

    # @return [Boolean]
    def exit?
      phase == :exit
    end

    # @return [String]
    def to_s
      call = "#{syscall.name}(#{formatted_args})"
      return "#{call} ..." if enter?

      "#{call} = #{formatted_return_value}"
    end

    # @return [String]
    def formatted_args
      args.each_with_index.map do |value, index|
        type = syscall.arg_types.fetch(index, nil)
        format_argument(type, value, index)
      end.join(", ")
    end

    # @return [String]
    def formatted_return_value
      return "?" if return_value.nil?
      return return_value.to_s unless syscall_error_code?(return_value)

      errno = -return_value
      name = ERRNO_NAME_BY_NUMBER.fetch(errno, "ERRNO_#{errno}")
      message = SystemCallError.new(errno).message
      "-1 #{name} (#{message})"
    end

    private

    def format_argument(type, value, index)
      case type
      when :str
        format_string_pointer(value)
      when :ptr, :buf
        format_pointer(value)
      when :flags
        format_flags(value, index: index)
      when :mode
        format_mode(value)
      when :fd, :int, :uint, :size, :pid
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

    def format_flags(value, index:)
      number = Integer(value)

      if open_flags_argument?(index)
        decode_open_flags(number)
      else
        format("0x%x", number)
      end
    end

    def format_mode(value)
      number = Integer(value)
      return "0" if number.zero?

      format("0%o", number)
    end

    def open_flags_argument?(index)
      return false unless %i[open openat].include?(syscall.name)

      flag_arg_name = syscall.arg_names.fetch(index, nil)
      flag_arg_name == :flags
    end

    def decode_open_flags(value)
      names = []

      access = value & OPEN_ACCESS_MASK
      names << OPEN_ACCESS_NAMES.fetch(access, format("0x%x", access))

      remaining = value & ~OPEN_ACCESS_MASK
      OPEN_FLAG_NAMES.keys.sort.reverse_each do |bit|
        next if bit.zero?
        next unless (remaining & bit) == bit

        names << OPEN_FLAG_NAMES.fetch(bit)
        remaining &= ~bit
      end

      names << format("0x%x", remaining) unless remaining.zero?
      names.join("|")
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

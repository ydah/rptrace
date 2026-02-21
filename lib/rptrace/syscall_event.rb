# frozen_string_literal: true

require "fcntl"

module Rptrace
  # Renderable syscall event (enter/exit).
  class SyscallEvent
    # Map of errno number to symbolic name (e.g., 2 => "ENOENT").
    ERRNO_NAME_BY_NUMBER = Errno.constants.each_with_object({}) do |const_name, map|
      errno_class = Errno.const_get(const_name)
      next unless errno_class.is_a?(Class) && errno_class < SystemCallError
      next unless errno_class.const_defined?(:Errno)

      map[errno_class::Errno] ||= const_name.to_s
    rescue NameError
      next
    end.freeze
    # Linux kernel upper bound for -errno syscall return convention.
    LINUX_MAX_ERRNO = 4095
    # Access mode mask for open/openat flags.
    OPEN_ACCESS_MASK = Fcntl.const_defined?(:O_ACCMODE) ? Fcntl::O_ACCMODE : 0x3
    # Mapping of open access mode value to symbolic name.
    OPEN_ACCESS_NAMES = {
      (Fcntl.const_defined?(:O_RDONLY) ? Fcntl::O_RDONLY : 0) => "O_RDONLY",
      (Fcntl.const_defined?(:O_WRONLY) ? Fcntl::O_WRONLY : 1) => "O_WRONLY",
      (Fcntl.const_defined?(:O_RDWR) ? Fcntl::O_RDWR : 2) => "O_RDWR"
    }.freeze
    # Mapping of open/openat modifier bits to symbolic names.
    OPEN_FLAG_NAMES = %i[
      O_APPEND O_ASYNC O_CLOEXEC O_CREAT O_DIRECT O_DIRECTORY O_DSYNC O_EXCL O_LARGEFILE
      O_NOATIME O_NOCTTY O_NOFOLLOW O_NONBLOCK O_PATH O_SYNC O_TMPFILE O_TRUNC
    ].each_with_object({}) do |const_name, map|
      next unless Fcntl.const_defined?(const_name)

      value = Fcntl.const_get(const_name)
      next unless value.is_a?(Integer) && value.positive?

      map[value] = const_name.to_s
    end.freeze
    # Mapping of PROT_* values used by mmap/mprotect.
    PROT_NAMES = %i[
      PROT_EXEC PROT_GROWSDOWN PROT_GROWSUP PROT_NONE PROT_READ PROT_SEM PROT_WRITE
    ].each_with_object({}) do |const_name, map|
      next unless Fcntl.const_defined?(const_name)

      value = Fcntl.const_get(const_name)
      next unless value.is_a?(Integer)

      map[value] = const_name.to_s
    end.freeze
    # Bit mask for MAP_* type field.
    MAP_TYPE_MASK = Fcntl.const_defined?(:MAP_TYPE) ? Fcntl::MAP_TYPE : nil
    # Mapping of mmap type flags.
    MAP_TYPE_NAMES = %i[
      MAP_PRIVATE MAP_SHARED MAP_SHARED_VALIDATE
    ].each_with_object({}) do |const_name, map|
      next unless Fcntl.const_defined?(const_name)

      value = Fcntl.const_get(const_name)
      next unless value.is_a?(Integer)

      map[value] = const_name.to_s
    end.freeze
    # Mapping of additional mmap modifier bits.
    MAP_FLAG_NAMES = %i[
      MAP_32BIT MAP_ANONYMOUS MAP_ANON MAP_DENYWRITE MAP_EXECUTABLE MAP_FILE
      MAP_FIXED MAP_FIXED_NOREPLACE MAP_GROWSDOWN MAP_HUGETLB MAP_LOCKED MAP_NONBLOCK
      MAP_NORESERVE MAP_POPULATE MAP_STACK MAP_SYNC MAP_UNINITIALIZED
    ].each_with_object({}) do |const_name, map|
      next unless Fcntl.const_defined?(const_name)

      value = Fcntl.const_get(const_name)
      next unless value.is_a?(Integer) && value.positive?

      map[value] ||= const_name.to_s
    end.freeze
    # Mapping of clone(2) flag bits in the upper bits of clone flags argument.
    CLONE_FLAG_NAMES = {
      0x0000_0100 => "CLONE_VM",
      0x0000_0200 => "CLONE_FS",
      0x0000_0400 => "CLONE_FILES",
      0x0000_0800 => "CLONE_SIGHAND",
      0x0000_1000 => "CLONE_PIDFD",
      0x0000_2000 => "CLONE_PTRACE",
      0x0000_4000 => "CLONE_VFORK",
      0x0000_8000 => "CLONE_PARENT",
      0x0001_0000 => "CLONE_THREAD",
      0x0002_0000 => "CLONE_NEWNS",
      0x0004_0000 => "CLONE_SYSVSEM",
      0x0008_0000 => "CLONE_SETTLS",
      0x0010_0000 => "CLONE_PARENT_SETTID",
      0x0020_0000 => "CLONE_CHILD_CLEARTID",
      0x0040_0000 => "CLONE_DETACHED",
      0x0080_0000 => "CLONE_UNTRACED",
      0x0100_0000 => "CLONE_CHILD_SETTID",
      0x0200_0000 => "CLONE_NEWCGROUP",
      0x0400_0000 => "CLONE_NEWUTS",
      0x0800_0000 => "CLONE_NEWIPC",
      0x1000_0000 => "CLONE_NEWUSER",
      0x2000_0000 => "CLONE_NEWPID",
      0x4000_0000 => "CLONE_NEWNET",
      0x8000_0000 => "CLONE_IO"
    }.freeze
    # Mapping of wait4(2) option bits.
    WAIT_OPTION_NAMES = {
      Constants::WNOHANG => "WNOHANG",
      Constants::WUNTRACED => "WUNTRACED",
      Constants::WCONTINUED => "WCONTINUED",
      Constants::WALL => "__WALL"
    }.freeze

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
    rescue Rptrace::Error, StandardError
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
      elsif mmap_prot_argument?(index)
        decode_mmap_prot(number)
      elsif mmap_flags_argument?(index)
        decode_mmap_flags(number)
      elsif clone_flags_argument?(index)
        decode_clone_flags(number)
      elsif wait_options_argument?(index)
        decode_wait_options(number)
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

    def mmap_prot_argument?(index)
      return false unless syscall.name == :mmap

      syscall.arg_names.fetch(index, nil) == :prot
    end

    def mmap_flags_argument?(index)
      return false unless syscall.name == :mmap

      syscall.arg_names.fetch(index, nil) == :flags
    end

    def clone_flags_argument?(index)
      return false unless syscall.name == :clone

      syscall.arg_names.fetch(index, nil) == :flags
    end

    def wait_options_argument?(index)
      return false unless syscall.name == :wait4

      syscall.arg_names.fetch(index, nil) == :options
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

    def decode_mmap_prot(value)
      return PROT_NAMES.fetch(0, "0") if value.zero?

      names = []
      remaining = value
      PROT_NAMES.keys.sort.each do |bit|
        next if bit.zero?
        next unless (remaining & bit) == bit

        names << PROT_NAMES.fetch(bit)
        remaining &= ~bit
      end

      names << format("0x%x", remaining) unless remaining.zero?
      names.empty? ? format("0x%x", value) : names.join("|")
    end

    def decode_mmap_flags(value)
      names = []
      remaining = value

      if MAP_TYPE_MASK
        map_type = value & MAP_TYPE_MASK
        names << MAP_TYPE_NAMES.fetch(map_type, format("0x%x", map_type)) unless map_type.zero?
        remaining &= ~MAP_TYPE_MASK
      end

      MAP_FLAG_NAMES.keys.sort.each do |bit|
        next unless (remaining & bit) == bit

        names << MAP_FLAG_NAMES.fetch(bit)
        remaining &= ~bit
      end

      names << format("0x%x", remaining) unless remaining.zero?
      names.empty? ? format("0x%x", value) : names.join("|")
    end

    def decode_clone_flags(value)
      names = []
      exit_signal = value & 0xFF
      remaining = value & ~0xFF

      CLONE_FLAG_NAMES.keys.sort.each do |bit|
        next unless (remaining & bit) == bit

        names << CLONE_FLAG_NAMES.fetch(bit)
        remaining &= ~bit
      end

      names << format_clone_exit_signal(exit_signal) unless exit_signal.zero?
      names << format("0x%x", remaining) unless remaining.zero?
      names.empty? ? "0" : names.join("|")
    end

    def format_clone_exit_signal(signal)
      signal_name = Signal.signame(signal)
      signal_name.start_with?("SIG") ? signal_name : "SIG#{signal_name}"
    rescue ArgumentError
      signal.to_s
    end

    def decode_wait_options(value)
      return "0" if value.zero?

      names = []
      remaining = value
      WAIT_OPTION_NAMES.keys.sort.each do |bit|
        next unless (remaining & bit) == bit

        names << WAIT_OPTION_NAMES.fetch(bit)
        remaining &= ~bit
      end

      names << format("0x%x", remaining) unless remaining.zero?
      names.empty? ? format("0x%x", value) : names.join("|")
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

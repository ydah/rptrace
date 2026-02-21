# frozen_string_literal: true

module Rptrace
  # Traced process handle for process control, register, and memory access.
  class Tracee
    attr_reader :pid, :registers, :memory

    # Default ptrace options set after spawn/attach.
    DEFAULT_TRACE_OPTIONS = Constants::PTRACE_O_TRACESYSGOOD
    # Register layout used for syscall number/args/return by architecture.
    SYSCALL_REGISTERS = {
      x86_64: {
        number: :orig_rax,
        args: %i[rdi rsi rdx r10 r8 r9],
        return_value: :rax
      }.freeze,
      aarch64: {
        number: :x8,
        args: %i[x0 x1 x2 x3 x4 x5],
        return_value: :x0
      }.freeze
    }.freeze
    # x86 INT3 software breakpoint opcode byte.
    BREAKPOINT_OPCODE = "\xCC".b
    # Seccomp metadata flag numeric value to symbolic tag.
    SECCOMP_METADATA_FLAG_NAMES = {
      Constants::SECCOMP_FILTER_FLAG_TSYNC => :tsync,
      Constants::SECCOMP_FILTER_FLAG_LOG => :log,
      Constants::SECCOMP_FILTER_FLAG_SPEC_ALLOW => :spec_allow,
      Constants::SECCOMP_FILTER_FLAG_NEW_LISTENER => :new_listener,
      Constants::SECCOMP_FILTER_FLAG_TSYNC_ESRCH => :tsync_esrch
    }.freeze

    def initialize(pid)
      @pid = Integer(pid)
      @registers = Registers.new(self)
      @memory = Memory.new(self)
    end

    # Spawns a new tracee process.
    #
    # @param command [String]
    # @param args [Array<String>]
    # @param options [Integer] ptrace option mask for PTRACE_SETOPTIONS
    # @return [Rptrace::Tracee]
    def self.spawn(command, *args, options: DEFAULT_TRACE_OPTIONS)
      child_pid = Process.fork do
        Binding.safe_ptrace(Constants::PTRACE_TRACEME, 0, 0, 0)
        exec(command, *args)
      rescue StandardError
        exit!(127)
      end

      raise Error, "fork failed" unless child_pid

      tracee = new(child_pid)
      initial_event = tracee.wait(flags: Constants::WALL)
      ensure_stopped!(event: initial_event, pid: child_pid, action: :spawn)
      configure_trace_options(pid: child_pid, options: options)
      tracee
    end

    # Attaches to an existing process.
    #
    # @param pid [Integer]
    # @param options [Integer] ptrace option mask for PTRACE_SETOPTIONS
    # @return [Rptrace::Tracee]
    def self.attach(pid, options: DEFAULT_TRACE_OPTIONS)
      pid = Integer(pid)
      Binding.safe_ptrace(Constants::PTRACE_ATTACH, pid, 0, 0)
      tracee = new(pid)
      initial_event = tracee.wait(flags: Constants::WALL)
      ensure_stopped!(event: initial_event, pid: pid, action: :attach)
      configure_trace_options(pid: pid, options: options)
      tracee
    end

    # Seizes an existing process without stopping it immediately.
    #
    # @param pid [Integer]
    # @param options [Integer] ptrace seize options
    # @return [Rptrace::Tracee]
    def self.seize(pid, options: 0)
      pid = Integer(pid)
      Binding.safe_ptrace(Constants::PTRACE_SEIZE, pid, 0, options)
      new(pid)
    end

    # Waits for any traced process/thread state change.
    #
    # @param flags [Integer] waitpid flags
    # @return [Rptrace::Event]
    def self.wait_any(flags: 0)
      waited_pid, status = Binding.safe_waitpid(-1, flags: flags)
      Event.new(waited_pid, status)
    end

    # Continue process execution.
    #
    # @param signal [Integer] signal number to inject
    # @return [Rptrace::Tracee]
    def cont(signal: 0)
      request(Constants::PTRACE_CONT, signal)
      self
    end

    # Resume process until next syscall stop.
    #
    # @param signal [Integer] signal number to inject
    # @return [Rptrace::Tracee]
    def syscall(signal: 0)
      request(Constants::PTRACE_SYSCALL, signal)
      self
    end

    # Single-step one instruction.
    #
    # @param signal [Integer] signal number to inject
    # @return [Rptrace::Tracee]
    def singlestep(signal: 0)
      request(Constants::PTRACE_SINGLESTEP, signal)
      self
    end

    # Detach from process.
    #
    # @param signal [Integer] signal number to deliver on detach
    # @return [Rptrace::Tracee]
    def detach(signal: 0)
      request(Constants::PTRACE_DETACH, signal)
      self
    end

    # Interrupt a seized process.
    #
    # @return [Rptrace::Tracee]
    def interrupt
      request(Constants::PTRACE_INTERRUPT, 0)
      self
    end

    # Resumes a tracee in ptrace-listen mode.
    #
    # @return [Rptrace::Tracee]
    def listen
      request(Constants::PTRACE_LISTEN, 0)
      self
    end

    # Sets ptrace options mask for this tracee.
    #
    # @param options [Integer] bitmask of PTRACE_O_* flags
    # @return [Rptrace::Tracee]
    def set_options(options)
      Binding.safe_ptrace(Constants::PTRACE_SETOPTIONS, pid, 0, Integer(options))
      self
    end

    # Enables seccomp tracing with syscall-stop distinction.
    #
    # @return [Rptrace::Tracee]
    def enable_seccomp_events!
      set_options(Constants::PTRACE_O_TRACESYSGOOD | Constants::PTRACE_O_TRACESECCOMP)
    end

    # Force-kill process.
    #
    # @return [Integer] signal result
    def kill
      Process.kill("KILL", pid)
    end

    # Wait for process state change.
    #
    # @param flags [Integer] waitpid flags
    # @return [Rptrace::Event]
    def wait(flags: 0)
      waited_pid, status = Binding.safe_waitpid(pid, flags: flags)
      Event.new(waited_pid, status)
    end

    # Current syscall metadata.
    #
    # @param arch [Symbol]
    # @return [Rptrace::Syscall::SyscallInfo]
    def current_syscall(arch: CStructs.arch)
      layout = syscall_layout(arch)
      Syscall.from_number(registers[layout.fetch(:number)], arch: arch)
    end

    # Current syscall argument register values.
    #
    # @param arch [Symbol]
    # @return [Array<Integer>]
    def syscall_args(arch: CStructs.arch)
      layout = syscall_layout(arch)
      layout.fetch(:args).map { |reg| registers[reg] }
    end

    # Current syscall return register value.
    #
    # @param arch [Symbol]
    # @return [Integer]
    def syscall_return(arch: CStructs.arch)
      layout = syscall_layout(arch)
      registers[layout.fetch(:return_value)]
    end

    # Parses current process memory mappings from /proc/<pid>/maps.
    #
    # @return [Array<Rptrace::ProcMaps::Mapping>]
    def memory_maps
      ProcMaps.read(pid)
    end

    # Reads ptrace event message (e.g., child pid for fork/clone events).
    #
    # @return [Integer]
    def event_message
      buffer = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP)
      Binding.safe_ptrace(Constants::PTRACE_GETEVENTMSG, pid, 0, buffer.to_i)
      buffer[0, Fiddle::SIZEOF_VOIDP].unpack1("J")
    end

    # Reads 32-bit seccomp filter data from ptrace event message.
    #
    # @return [Integer]
    def seccomp_data
      event_message & 0xFFFF_FFFF
    end

    # Returns seccomp filter metadata for given filter index.
    #
    # @param index [Integer]
    # @return [Hash<Symbol, Integer>] keys: :filter_off, :flags
    def seccomp_metadata(index: 0)
      filter_index = normalize_non_negative_index(index, label: :index)
      metadata = CStructs.pack_seccomp_metadata(filter_off: filter_index, flags: 0)
      pointer = Fiddle::Pointer.malloc(CStructs.seccomp_metadata_size)
      pointer[0, metadata.bytesize] = metadata
      Binding.safe_ptrace(Constants::PTRACE_SECCOMP_GET_METADATA, pid, CStructs.seccomp_metadata_size, pointer.to_i)
      CStructs.unpack_seccomp_metadata(pointer[0, CStructs.seccomp_metadata_size])
    end

    # Returns decoded seccomp BPF instructions for given filter index.
    #
    # @param index [Integer]
    # @return [Array<Hash<Symbol, Integer>>]
    def seccomp_filter(index: 0)
      filter_index = normalize_non_negative_index(index, label: :index)
      insn_count = seccomp_filter_instruction_count(index: filter_index)
      return [] if insn_count <= 0

      byte_length = insn_count * CStructs::SECCOMP_FILTER_INSN_SIZE
      pointer = Fiddle::Pointer.malloc(byte_length)
      copied = Binding.safe_ptrace(Constants::PTRACE_SECCOMP_GET_FILTER, pid, filter_index, pointer.to_i)
      copied_count = Integer(copied)
      CStructs.decode_seccomp_filter(pointer[0, copied_count * CStructs::SECCOMP_FILTER_INSN_SIZE])
    end

    # Returns true when kernel supports seccomp metadata query for this tracee.
    #
    # @return [Boolean]
    def seccomp_supported?
      seccomp_metadata(index: 0)
      true
    rescue InvalidArgError
      false
    end

    # Returns true when tracee has seccomp filter instructions available at index.
    #
    # @param index [Integer]
    # @return [Boolean]
    def seccomp_filter_available?(index: 0)
      seccomp_filter_instruction_count(index: index).positive?
    rescue InvalidArgError
      false
    end

    # Returns symbolic names for seccomp metadata flags.
    #
    # @param index [Integer]
    # @return [Array<Symbol>]
    def seccomp_metadata_flag_names(index: 0)
      decode_seccomp_metadata_flags(seccomp_metadata(index: index).fetch(:flags))
    end

    # Returns active software breakpoints.
    #
    # @return [Array<Rptrace::Breakpoint>]
    def breakpoints
      breakpoint_store.values
    end

    # Looks up an active software breakpoint by address.
    #
    # @param address [Integer]
    # @return [Rptrace::Breakpoint, nil]
    def breakpoint(address)
      breakpoint_store[Integer(address)]
    end

    # Returns true when instruction pointer is currently on a known software breakpoint trap.
    #
    # @param arch [Symbol]
    # @return [Boolean]
    def breakpoint_hit?(arch: CStructs.arch)
      !!current_breakpoint(arch: arch)
    end

    # Returns current breakpoint at instruction pointer trap site.
    #
    # @param arch [Symbol]
    # @return [Rptrace::Breakpoint, nil]
    def current_breakpoint(arch: CStructs.arch)
      return nil unless arch.to_sym == :x86_64

      ip_reg = instruction_pointer_register(arch)
      ip = Integer(registers[ip_reg])
      return nil if ip <= 0

      breakpoint_store[ip - 1]
    end

    # Installs an x86_64 INT3 software breakpoint.
    #
    # @param address [Integer]
    # @return [Rptrace::Breakpoint]
    # @raise [Rptrace::UnsupportedArchError]
    def set_breakpoint(address)
      ensure_breakpoint_supported_arch!

      addr = Integer(address)
      existing = breakpoint_store[addr]
      return existing if existing&.enabled?

      original_byte = memory.read(addr, 1)
      memory.write(addr, BREAKPOINT_OPCODE)
      breakpoint_store[addr] = Breakpoint.new(tracee: self, address: addr, original_byte: original_byte)
    end

    # Restores a previously installed software breakpoint.
    #
    # @param address [Integer]
    # @return [Rptrace::Breakpoint, nil]
    def remove_breakpoint(address)
      addr = Integer(address)
      existing = breakpoint_store[addr]
      return nil unless existing

      memory.write(addr, existing.original_byte)
      existing.disable!
      breakpoint_store.delete(addr)
      existing
    end

    # Restores and removes all active software breakpoints.
    #
    # @return [Integer] number of removed breakpoints
    def clear_breakpoints
      count = 0
      breakpoint_store.keys.each do |addr|
        count += 1 if remove_breakpoint(addr)
      end
      count
    end

    # Executes one instruction over the currently hit software breakpoint and reinstalls it.
    #
    # @param signal [Integer] signal to inject during single-step
    # @param arch [Symbol]
    # @param wait_flags [Integer]
    # @return [Rptrace::Event]
    # @raise [Rptrace::Error]
    # @raise [Rptrace::UnsupportedArchError]
    def step_over_breakpoint(signal: 0, arch: CStructs.arch, wait_flags: Constants::WALL)
      ensure_breakpoint_supported_arch!
      breakpoint = current_breakpoint(arch: arch)
      raise Error, "no active breakpoint at current instruction pointer" unless breakpoint

      ip_reg = instruction_pointer_register(arch)
      address = breakpoint.address
      memory.write(address, breakpoint.original_byte)
      registers.write(ip_reg => address)
      singlestep(signal: signal)
      event = wait(flags: wait_flags)
      memory.write(address, BREAKPOINT_OPCODE) if breakpoint.enabled?
      event
    end

    private

    def request(request, signal)
      Binding.safe_ptrace(request, pid, 0, signal)
    end

    def syscall_layout(arch)
      SYSCALL_REGISTERS.fetch(arch.to_sym) do
        raise UnsupportedArchError, "unsupported syscall register layout for #{arch}"
      end
    end

    def breakpoint_store
      @breakpoint_store ||= {}
    end

    def ensure_breakpoint_supported_arch!
      arch = CStructs.arch
      return if arch == :x86_64

      raise UnsupportedArchError, "software breakpoints are supported only on x86_64 (got #{arch})"
    end

    def instruction_pointer_register(arch)
      case arch.to_sym
      when :x86_64 then :rip
      when :aarch64 then :pc
      else
        raise UnsupportedArchError, "unsupported instruction pointer register for #{arch}"
      end
    end

    def decode_seccomp_metadata_flags(flags)
      value = Integer(flags)
      names = []

      SECCOMP_METADATA_FLAG_NAMES.keys.sort.each do |bit|
        next unless (value & bit) == bit

        names << SECCOMP_METADATA_FLAG_NAMES.fetch(bit)
        value &= ~bit
      end

      names << :"unknown_0x#{value.to_s(16)}" unless value.zero?
      names
    end

    def seccomp_filter_instruction_count(index:)
      filter_index = normalize_non_negative_index(index, label: :index)
      Integer(Binding.safe_ptrace(Constants::PTRACE_SECCOMP_GET_FILTER, pid, filter_index, 0))
    end

    def normalize_non_negative_index(value, label:)
      int = Integer(value)
      raise ArgumentError, "#{label} must be non-negative" if int.negative?

      int
    end

    class << self
      private

      def configure_trace_options(pid:, options:)
        mask = Integer(options)
        return if mask.zero?

        Binding.safe_ptrace(Constants::PTRACE_SETOPTIONS, pid, 0, mask)
      end

      def ensure_stopped!(event:, pid:, action:)
        return if event.stopped?

        status = format("0x%<status>x", status: event.raw_status)
        raise Error, "tracee #{pid} did not stop after #{action} (status=#{status})"
      end
    end
  end
end

# frozen_string_literal: true

module Ptrace
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
    BREAKPOINT_OPCODE = "\xCC".b

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
    # @return [Ptrace::Tracee]
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
    # @return [Ptrace::Tracee]
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
    # @return [Ptrace::Tracee]
    def self.seize(pid, options: 0)
      pid = Integer(pid)
      Binding.safe_ptrace(Constants::PTRACE_SEIZE, pid, 0, options)
      new(pid)
    end

    # Waits for any traced process/thread state change.
    #
    # @param flags [Integer] waitpid flags
    # @return [Ptrace::Event]
    def self.wait_any(flags: 0)
      waited_pid, status = Binding.safe_waitpid(-1, flags: flags)
      Event.new(waited_pid, status)
    end

    # Continue process execution.
    #
    # @param signal [Integer] signal number to inject
    # @return [Ptrace::Tracee]
    def cont(signal: 0)
      request(Constants::PTRACE_CONT, signal)
      self
    end

    # Resume process until next syscall stop.
    #
    # @param signal [Integer] signal number to inject
    # @return [Ptrace::Tracee]
    def syscall(signal: 0)
      request(Constants::PTRACE_SYSCALL, signal)
      self
    end

    # Single-step one instruction.
    #
    # @param signal [Integer] signal number to inject
    # @return [Ptrace::Tracee]
    def singlestep(signal: 0)
      request(Constants::PTRACE_SINGLESTEP, signal)
      self
    end

    # Detach from process.
    #
    # @param signal [Integer] signal number to deliver on detach
    # @return [Ptrace::Tracee]
    def detach(signal: 0)
      request(Constants::PTRACE_DETACH, signal)
      self
    end

    # Interrupt a seized process.
    #
    # @return [Ptrace::Tracee]
    def interrupt
      request(Constants::PTRACE_INTERRUPT, 0)
      self
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
    # @return [Ptrace::Event]
    def wait(flags: 0)
      waited_pid, status = Binding.safe_waitpid(pid, flags: flags)
      Event.new(waited_pid, status)
    end

    # Current syscall metadata.
    #
    # @param arch [Symbol]
    # @return [Ptrace::Syscall::SyscallInfo]
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
    # @return [Array<Ptrace::ProcMaps::Mapping>]
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

    # Returns active software breakpoints.
    #
    # @return [Array<Ptrace::Breakpoint>]
    def breakpoints
      breakpoint_store.values
    end

    # Looks up an active software breakpoint by address.
    #
    # @param address [Integer]
    # @return [Ptrace::Breakpoint, nil]
    def breakpoint(address)
      breakpoint_store[Integer(address)]
    end

    # Installs an x86_64 INT3 software breakpoint.
    #
    # @param address [Integer]
    # @return [Ptrace::Breakpoint]
    # @raise [Ptrace::UnsupportedArchError]
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
    # @return [Ptrace::Breakpoint, nil]
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

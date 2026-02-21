# frozen_string_literal: true

module Ptrace
  class Tracee
    attr_reader :pid, :registers, :memory

    DEFAULT_TRACE_OPTIONS = Constants::PTRACE_O_TRACESYSGOOD
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

    def initialize(pid)
      @pid = Integer(pid)
      @registers = Registers.new(self)
      @memory = Memory.new(self)
    end

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

    def self.attach(pid, options: DEFAULT_TRACE_OPTIONS)
      pid = Integer(pid)
      Binding.safe_ptrace(Constants::PTRACE_ATTACH, pid, 0, 0)
      tracee = new(pid)
      initial_event = tracee.wait(flags: Constants::WALL)
      ensure_stopped!(event: initial_event, pid: pid, action: :attach)
      configure_trace_options(pid: pid, options: options)
      tracee
    end

    def self.seize(pid, options: 0)
      pid = Integer(pid)
      Binding.safe_ptrace(Constants::PTRACE_SEIZE, pid, 0, options)
      new(pid)
    end

    def cont(signal: 0)
      request(Constants::PTRACE_CONT, signal)
      self
    end

    def syscall(signal: 0)
      request(Constants::PTRACE_SYSCALL, signal)
      self
    end

    def singlestep(signal: 0)
      request(Constants::PTRACE_SINGLESTEP, signal)
      self
    end

    def detach(signal: 0)
      request(Constants::PTRACE_DETACH, signal)
      self
    end

    def interrupt
      request(Constants::PTRACE_INTERRUPT, 0)
      self
    end

    def kill
      Process.kill("KILL", pid)
    end

    def wait(flags: 0)
      waited_pid, status = Binding.safe_waitpid(pid, flags: flags)
      Event.new(waited_pid, status)
    end

    def current_syscall(arch: CStructs.arch)
      layout = syscall_layout(arch)
      Syscall.from_number(registers[layout.fetch(:number)], arch: arch)
    end

    def syscall_args(arch: CStructs.arch)
      layout = syscall_layout(arch)
      layout.fetch(:args).map { |reg| registers[reg] }
    end

    def syscall_return(arch: CStructs.arch)
      layout = syscall_layout(arch)
      registers[layout.fetch(:return_value)]
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

# frozen_string_literal: true

module Ptrace
  class Tracee
    attr_reader :pid, :registers, :memory

    def initialize(pid)
      @pid = Integer(pid)
      @registers = Registers.new(self)
      @memory = Memory.new(self)
    end

    def self.spawn(command, *args)
      child_pid = Process.fork do
        Binding.safe_ptrace(Constants::PTRACE_TRACEME, 0, 0, 0)
        exec(command, *args)
      rescue StandardError
        exit!(127)
      end

      raise Error, "fork failed" unless child_pid

      tracee = new(child_pid)
      tracee.wait(flags: Constants::__WALL)
      Binding.safe_ptrace(
        Constants::PTRACE_SETOPTIONS,
        child_pid,
        0,
        Constants::PTRACE_O_TRACESYSGOOD
      )
      tracee
    end

    def self.attach(pid)
      pid = Integer(pid)
      Binding.safe_ptrace(Constants::PTRACE_ATTACH, pid, 0, 0)
      tracee = new(pid)
      tracee.wait(flags: Constants::__WALL)
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

    def current_syscall
      Syscall.from_number(registers[:orig_rax])
    end

    def syscall_args
      %i[rdi rsi rdx r10 r8 r9].map { |reg| registers[reg] }
    end

    def syscall_return
      registers[:rax]
    end

    private

    def request(request, signal)
      Binding.safe_ptrace(request, pid, 0, signal)
    end
  end
end

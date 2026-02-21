# frozen_string_literal: true

module Ptrace
  class << self
    def trace(command, *args)
      tracee = Tracee.spawn(command, *args)
      yield tracee
    ensure
      begin
        tracee&.detach
      rescue Error, Errno::ESRCH
        nil
      end
    end

    def strace(command, *args)
      trace(command, *args) do |tracee|
        loop do
          tracee.syscall
          event = tracee.wait(flags: Constants::WALL)
          break if event.exited? || event.signaled?
          next unless event.syscall_stop?

          syscall = tracee.current_syscall
          syscall_args = tracee.syscall_args

          yield SyscallEvent.new(tracee: tracee, syscall: syscall, args: syscall_args, phase: :enter)

          tracee.syscall
          exit_event = tracee.wait(flags: Constants::WALL)
          break if exit_event.exited? || exit_event.signaled?

          yield SyscallEvent.new(
            tracee: tracee,
            syscall: syscall,
            args: syscall_args,
            return_value: tracee.syscall_return,
            phase: :exit
          )
        end
      end
    end
  end
end

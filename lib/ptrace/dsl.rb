# frozen_string_literal: true

module Ptrace
  class << self
    FOLLOW_CHILD_TRACE_OPTIONS = Tracee::DEFAULT_TRACE_OPTIONS |
      Constants::PTRACE_O_TRACECLONE |
      Constants::PTRACE_O_TRACEFORK |
      Constants::PTRACE_O_TRACEVFORK

    # Spawns and traces a command for the duration of the block.
    #
    # @param command [String] executable path or command name
    # @param args [Array<String>] command arguments
    # @param options [Integer] ptrace options passed to Tracee.spawn
    # @yieldparam tracee [Ptrace::Tracee]
    # @return [Object] block return value
    def trace(command, *args, options: Tracee::DEFAULT_TRACE_OPTIONS)
      tracee = Tracee.spawn(command, *args, options: options)
      yield tracee
    ensure
      safe_detach(tracee)
    end

    # Runs a command and yields syscall enter/exit events.
    #
    # @param command [String] executable path or command name
    # @param args [Array<String>] command arguments
    # @param follow_children [Boolean] follow clone/fork/vfork descendants
    # @yieldparam event [Ptrace::SyscallEvent]
    # @return [void]
    def strace(command, *args, follow_children: false)
      options = follow_children ? FOLLOW_CHILD_TRACE_OPTIONS : Tracee::DEFAULT_TRACE_OPTIONS
      trace(command, *args, options: options) do |tracee|
        if follow_children
          strace_with_children(tracee) { |event| yield event }
        else
          strace_single(tracee) { |event| yield event }
        end
      end
    end

    private

    def strace_single(tracee)
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

    def strace_with_children(root_tracee)
      tracees = { root_tracee.pid => root_tracee }
      pending_syscalls = {}
      root_tracee.syscall

      while tracees.any?
        event = Tracee.wait_any(flags: Constants::WALL)
        tracee = tracees.fetch(event.pid) { tracees[event.pid] = Tracee.new(event.pid) }

        if event.exited? || event.signaled?
          pending_syscalls.delete(event.pid)
          tracees.delete(event.pid)
          next
        end

        if fork_like_event?(event)
          child_pid = tracee.event_message
          child_tracee = tracees.fetch(child_pid) do
            created = Tracee.new(child_pid)
            created.set_options(FOLLOW_CHILD_TRACE_OPTIONS)
            tracees[child_pid] = created
          end
          pending_syscalls.delete(child_pid)
          child_tracee.syscall
        end

        if event.syscall_stop?
          if pending_syscalls.key?(event.pid)
            entry = pending_syscalls.delete(event.pid)
            yield SyscallEvent.new(
              tracee: tracee,
              syscall: entry.fetch(:syscall),
              args: entry.fetch(:args),
              return_value: tracee.syscall_return,
              phase: :exit
            )
          else
            syscall = tracee.current_syscall
            syscall_args = tracee.syscall_args
            pending_syscalls[event.pid] = { syscall: syscall, args: syscall_args }
            yield SyscallEvent.new(tracee: tracee, syscall: syscall, args: syscall_args, phase: :enter)
          end
        end

        tracee.syscall
      end
    ensure
      tracees&.each_value { |tracee| safe_detach(tracee) }
    end

    def fork_like_event?(event)
      event.clone_event? || event.fork_event? || event.vfork_event?
    end

    def safe_detach(tracee)
      begin
        tracee&.detach
      rescue Error, Errno::ESRCH
        nil
      end
    end
  end
end

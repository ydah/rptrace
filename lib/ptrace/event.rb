# frozen_string_literal: true

module Ptrace
  # waitpid status wrapper with ptrace-specific helpers.
  class Event
    attr_reader :pid, :raw_status

    def initialize(pid, raw_status)
      @pid = Integer(pid)
      @raw_status = Integer(raw_status)
    end

    # @return [Boolean]
    def stopped?
      WaitStatus.stopped?(raw_status)
    end

    # @return [Boolean]
    def exited?
      WaitStatus.exited?(raw_status)
    end

    # @return [Boolean]
    def signaled?
      WaitStatus.signaled?(raw_status)
    end

    # @return [Boolean]
    def continued?
      WaitStatus.continued?(raw_status)
    end

    # @return [Integer]
    def stop_signal
      WaitStatus.stop_signal(raw_status)
    end

    # @return [Integer]
    def exit_status
      WaitStatus.exit_status(raw_status)
    end

    # @return [Integer]
    def term_signal
      WaitStatus.term_signal(raw_status)
    end

    # @return [Boolean]
    def syscall_stop?
      stopped? && stop_signal == (Signal.list.fetch("TRAP") | 0x80)
    end

    # @return [Integer]
    def event_code
      (raw_status >> 16) & 0xFFFF
    end

    def fork_event?
      event_code == Constants::PTRACE_EVENT_FORK
    end

    def clone_event?
      event_code == Constants::PTRACE_EVENT_CLONE
    end

    def exec_event?
      event_code == Constants::PTRACE_EVENT_EXEC
    end

    def exit_event?
      event_code == Constants::PTRACE_EVENT_EXIT
    end

    def inspect
      "#<#{self.class} pid=#{pid} status=0x#{raw_status.to_s(16)}>"
    end
  end
end

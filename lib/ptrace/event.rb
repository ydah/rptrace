# frozen_string_literal: true

module Ptrace
  class Event
    attr_reader :pid, :raw_status

    def initialize(pid, raw_status)
      @pid = Integer(pid)
      @raw_status = Integer(raw_status)
    end

    def stopped?
      WaitStatus.stopped?(raw_status)
    end

    def exited?
      WaitStatus.exited?(raw_status)
    end

    def signaled?
      WaitStatus.signaled?(raw_status)
    end

    def continued?
      WaitStatus.continued?(raw_status)
    end

    def stop_signal
      WaitStatus.stop_signal(raw_status)
    end

    def exit_status
      WaitStatus.exit_status(raw_status)
    end

    def term_signal
      WaitStatus.term_signal(raw_status)
    end

    def syscall_stop?
      stopped? && stop_signal == (Signal.list.fetch("TRAP") | 0x80)
    end

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

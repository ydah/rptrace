# frozen_string_literal: true

module Rptrace
  # waitpid status wrapper with ptrace-specific helpers.
  class Event
    # ptrace event code to symbolic name map for inspect output.
    EVENT_NAME_BY_CODE = {
      Constants::PTRACE_EVENT_FORK => "fork",
      Constants::PTRACE_EVENT_VFORK => "vfork",
      Constants::PTRACE_EVENT_CLONE => "clone",
      Constants::PTRACE_EVENT_EXEC => "exec",
      Constants::PTRACE_EVENT_VFORK_DONE => "vfork_done",
      Constants::PTRACE_EVENT_EXIT => "exit",
      Constants::PTRACE_EVENT_SECCOMP => "seccomp",
      Constants::PTRACE_EVENT_STOP => "stop"
    }.freeze

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

    def vfork_event?
      event_code == Constants::PTRACE_EVENT_VFORK
    end

    def vfork_done_event?
      event_code == Constants::PTRACE_EVENT_VFORK_DONE
    end

    def exec_event?
      event_code == Constants::PTRACE_EVENT_EXEC
    end

    def exit_event?
      event_code == Constants::PTRACE_EVENT_EXIT
    end

    def seccomp_event?
      event_code == Constants::PTRACE_EVENT_SECCOMP
    end

    # @return [Boolean]
    def fork_like_event?
      fork_event? || clone_event? || vfork_event?
    end

    # @return [String]
    def inspect
      "#<#{self.class} pid=#{pid} status=0x#{raw_status.to_s(16)} #{state_summary}>"
    end

    private

    def state_summary
      return "state=syscall_stop" if syscall_stop?
      return "state=exited(#{exit_status})" if exited?
      return "state=continued" if continued?
      if stopped?
        event_name = EVENT_NAME_BY_CODE[event_code]
        summary = "state=stopped(#{signal_label(stop_signal)})"
        return "#{summary} event=#{event_name}" if event_name

        return summary
      end
      return "state=signaled(#{signal_label(term_signal)})" if signaled?

      "state=unknown"
    end

    def signal_label(number)
      signal_name = Signal.signame(number)
      signal_name = "SIG#{signal_name}" unless signal_name.start_with?("SIG")
      signal_name
    rescue ArgumentError
      "SIG#{number}"
    end
  end
end

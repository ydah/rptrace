# frozen_string_literal: true

module Ptrace
  # Runtime helpers to inspect ptrace permission-related environment.
  module Permission
    # Linux capability bit index for CAP_SYS_PTRACE.
    CAP_SYS_PTRACE_BIT = 19
    # Yama ptrace scope procfs path.
    YAMA_PTRACE_SCOPE_PATH = "/proc/sys/kernel/yama/ptrace_scope"
    # Process status procfs path.
    PROC_STATUS_PATH = "/proc/self/status"

    module_function

    # Returns Yama ptrace_scope value, or nil when unavailable.
    #
    # @return [Integer, nil]
    def ptrace_scope
      return nil unless File.readable?(YAMA_PTRACE_SCOPE_PATH)

      Integer(File.read(YAMA_PTRACE_SCOPE_PATH).strip, 10)
    rescue StandardError
      nil
    end

    # Returns effective Linux capabilities bitmask from /proc/self/status.
    #
    # @return [Integer, nil]
    def effective_capabilities_mask
      return nil unless File.readable?(PROC_STATUS_PATH)

      text = File.read(PROC_STATUS_PATH)
      cap_eff = text[/^CapEff:\s*([0-9A-Fa-f]+)\s*$/, 1]
      return nil unless cap_eff

      Integer(cap_eff, 16)
    rescue StandardError
      nil
    end

    # Returns true when process has CAP_SYS_PTRACE capability.
    #
    # @return [Boolean]
    def cap_sys_ptrace?
      mask = effective_capabilities_mask
      return false unless mask

      (mask & (1 << CAP_SYS_PTRACE_BIT)).positive?
    end

    # Returns true when process is root or has CAP_SYS_PTRACE.
    #
    # @return [Boolean]
    def privileged_for_ptrace?
      Process.euid.zero? || cap_sys_ptrace?
    end

    # Returns a diagnostic hash and actionable hints for ptrace setup.
    #
    # @return [Hash]
    def diagnostics
      scope = ptrace_scope
      has_cap = cap_sys_ptrace?
      privileged = Process.euid.zero? || has_cap
      hints = []

      unless privileged
        hints << "run as root or grant CAP_SYS_PTRACE"
      end
      hints << "set /proc/sys/kernel/yama/ptrace_scope to 0 or 1" if scope && scope > 1

      {
        uid: Process.uid,
        euid: Process.euid,
        ptrace_privileged: privileged,
        cap_sys_ptrace: has_cap,
        yama_ptrace_scope: scope,
        hints: hints
      }
    end
  end
end

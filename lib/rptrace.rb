# frozen_string_literal: true

require "rbconfig"

require_relative "rptrace/version"
require_relative "rptrace/error"
require_relative "rptrace/constants"
require_relative "rptrace/binding"
require_relative "rptrace/c_structs"
require_relative "rptrace/permission"
require_relative "rptrace/event"
require_relative "rptrace/registers"
require_relative "rptrace/memory"
require_relative "rptrace/breakpoint"
require_relative "rptrace/proc_maps"
require_relative "rptrace/syscall"
require_relative "rptrace/syscall_event"
require_relative "rptrace/seccomp_event"
require_relative "rptrace/tracee"
require_relative "rptrace/dsl"

# Linux ptrace wrapper.
module Rptrace
  class << self
    # @return [Boolean] true when running on Linux host OS
    def linux?
      /linux/.match?(RbConfig::CONFIG.fetch("host_os", ""))
    end

    # @return [Boolean] true when current process can generally ptrace (root or CAP_SYS_PTRACE)
    def ptrace_privileged?
      Permission.privileged_for_ptrace?
    end

    # @return [Hash] ptrace permission diagnostics
    def ptrace_permissions
      Permission.diagnostics
    end

    # Raises when current process lacks ptrace privilege and returns diagnostics otherwise.
    #
    # @param request [Symbol]
    # @return [Hash]
    # @raise [Rptrace::PermissionError]
    def ensure_ptrace_privileged!(request: :permission_check)
      Permission.ensure_privileged!(request: request)
    end
  end
end

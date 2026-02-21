# frozen_string_literal: true

require "rbconfig"

require_relative "ptrace/version"
require_relative "ptrace/error"
require_relative "ptrace/constants"
require_relative "ptrace/binding"
require_relative "ptrace/c_structs"
require_relative "ptrace/event"
require_relative "ptrace/registers"
require_relative "ptrace/memory"
require_relative "ptrace/breakpoint"
require_relative "ptrace/proc_maps"
require_relative "ptrace/syscall"
require_relative "ptrace/syscall_event"
require_relative "ptrace/tracee"
require_relative "ptrace/dsl"

# Linux ptrace wrapper.
module Ptrace
  class << self
    # @return [Boolean] true when running on Linux host OS
    def linux?
      /linux/.match?(RbConfig::CONFIG.fetch("host_os", ""))
    end
  end
end

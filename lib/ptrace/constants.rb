# frozen_string_literal: true

module Ptrace
  module Constants
    NT_PRSTATUS = 1

    PTRACE_TRACEME = 0
    PTRACE_PEEKTEXT = 1
    PTRACE_PEEKDATA = 2
    PTRACE_PEEKUSER = 3
    PTRACE_POKETEXT = 4
    PTRACE_POKEDATA = 5
    PTRACE_POKEUSER = 6
    PTRACE_CONT = 7
    PTRACE_KILL = 8
    PTRACE_SINGLESTEP = 9
    PTRACE_GETREGS = 12
    PTRACE_SETREGS = 13
    PTRACE_GETFPREGS = 14
    PTRACE_SETFPREGS = 15
    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    PTRACE_GETFPXREGS = 18
    PTRACE_SETFPXREGS = 19
    PTRACE_SYSCALL = 24
    PTRACE_SETOPTIONS = 0x4200
    PTRACE_GETEVENTMSG = 0x4201
    PTRACE_GETSIGINFO = 0x4202
    PTRACE_SETSIGINFO = 0x4203
    PTRACE_GETREGSET = 0x4204
    PTRACE_SETREGSET = 0x4205
    PTRACE_SEIZE = 0x4206
    PTRACE_INTERRUPT = 0x4207
    PTRACE_LISTEN = 0x4208
    PTRACE_PEEKSIGINFO = 0x4209
    PTRACE_GETSIGMASK = 0x420A
    PTRACE_SETSIGMASK = 0x420B
    PTRACE_SECCOMP_GET_FILTER = 0x420C
    PTRACE_SECCOMP_GET_METADATA = 0x420D
    PTRACE_GET_SYSCALL_INFO = 0x420E

    PTRACE_O_TRACESYSGOOD = 0x00000001
    PTRACE_O_TRACEFORK = 0x00000002
    PTRACE_O_TRACEVFORK = 0x00000004
    PTRACE_O_TRACECLONE = 0x00000008
    PTRACE_O_TRACEEXEC = 0x00000010
    PTRACE_O_TRACEVFORKDONE = 0x00000020
    PTRACE_O_TRACEEXIT = 0x00000040
    PTRACE_O_TRACESECCOMP = 0x00000080
    PTRACE_O_EXITKILL = 0x00100000
    PTRACE_O_SUSPEND_SECCOMP = 0x00200000

    PTRACE_EVENT_FORK = 1
    PTRACE_EVENT_VFORK = 2
    PTRACE_EVENT_CLONE = 3
    PTRACE_EVENT_EXEC = 4
    PTRACE_EVENT_VFORK_DONE = 5
    PTRACE_EVENT_EXIT = 6
    PTRACE_EVENT_SECCOMP = 7
    PTRACE_EVENT_STOP = 128

    WNOHANG = 1
    WUNTRACED = 2
    WCONTINUED = 8
    WALL = 0x40000000
  end

  module WaitStatus
    module_function

    def exited?(status)
      (status & 0x7F).zero?
    end

    def signaled?(status)
      (((status & 0x7F) + 1) >> 1).positive?
    end

    def stopped?(status)
      (status & 0xFF) == 0x7F
    end

    def continued?(status)
      status == 0xFFFF
    end

    def exit_status(status)
      (status >> 8) & 0xFF
    end

    def term_signal(status)
      status & 0x7F
    end

    def stop_signal(status)
      (status >> 8) & 0xFF
    end

    def core_dumped?(status)
      signaled?(status) && (status & 0x80).positive?
    end
  end
end

# frozen_string_literal: true

require "rbconfig"

RSpec.describe Ptrace::Tracee do
  INTEGRATION_ENV = "PTRACE_RUN_INTEGRATION"

  def ensure_integration_environment!
    skip "linux-only integration spec" unless Ptrace.linux?
    return if ENV[INTEGRATION_ENV] == "1"

    skip "set #{INTEGRATION_ENV}=1 to run ptrace integration specs"
  end

  def with_ptrace_permission
    yield
  rescue Ptrace::PermissionError => e
    skip "ptrace permission required: #{e.message}"
  end

  before do
    ensure_integration_environment!
  end

  it "spawns and traces /bin/true" do
    tracee = nil

    with_ptrace_permission do
      tracee = described_class.spawn("/bin/true")
      tracee.cont
      event = tracee.wait(flags: Ptrace::Constants::WALL)

      expect(event.exited?).to be(true)
      expect(event.exit_status).to eq(0)
    end
  ensure
    tracee&.detach
  end

  it "spawns and traces /bin/echo with arguments" do
    tracee = nil

    with_ptrace_permission do
      tracee = described_class.spawn("/bin/echo", "hello")
      tracee.cont
      event = tracee.wait(flags: Ptrace::Constants::WALL)

      expect(event.exited?).to be(true)
      expect(event.exit_status).to eq(0)
    end
  ensure
    tracee&.detach
  end

  it "can read registers and process memory while stopped" do
    tracee = nil

    with_ptrace_permission do
      tracee = described_class.spawn("/bin/true")
      regs = tracee.registers.read

      pc_reg, sp_reg = case Ptrace::CStructs.arch
                       when :x86_64 then %i[rip rsp]
                       when :aarch64 then %i[pc sp]
                       end

      expect(regs).to include(pc_reg, sp_reg)
      expect(regs.fetch(pc_reg)).to be_a(Integer)

      bytes = tracee.memory.read(regs.fetch(sp_reg), 16)
      expect(bytes.bytesize).to eq(16)

      tracee.cont
      event = tracee.wait(flags: Ptrace::Constants::WALL)
      expect(event.exited?).to be(true)
    end
  ensure
    tracee&.detach
  end

  it "reports syscall stops with PTRACE_SYSCALL" do
    tracee = nil

    with_ptrace_permission do
      tracee = described_class.spawn("/bin/true")

      seen_syscall_stop = false
      256.times do
        tracee.syscall
        event = tracee.wait(flags: Ptrace::Constants::WALL)

        break if event.exited? || event.signaled?
        next unless event.syscall_stop?

        seen_syscall_stop = true
        break
      end

      expect(seen_syscall_stop).to be(true)
    end
  ensure
    tracee&.detach
  end

  it "attaches and detaches from a running process" do
    tracee = nil
    child_pid = nil

    with_ptrace_permission do
      child_pid = Process.spawn("/bin/sleep", "2")
      tracee = described_class.attach(child_pid)

      expect(tracee.pid).to eq(child_pid)
      expect { tracee.detach }.not_to raise_error
      expect { Process.kill(0, child_pid) }.not_to raise_error
    end
  ensure
    begin
      tracee&.detach
    rescue Ptrace::Error, Errno::ESRCH
      nil
    end

    begin
      Process.kill("KILL", child_pid) if child_pid
    rescue Errno::ESRCH
      nil
    end

    begin
      Process.wait(child_pid) if child_pid
    rescue Errno::ECHILD
      nil
    end
  end

  it "seizes and interrupts a running process" do
    tracee = nil
    child_pid = nil

    with_ptrace_permission do
      child_pid = Process.spawn("/bin/sleep", "2")
      tracee = described_class.seize(child_pid, options: Ptrace::Constants::PTRACE_O_TRACESYSGOOD)
      tracee.interrupt
      event = tracee.wait(flags: Ptrace::Constants::WALL)

      expect(event.stopped?).to be(true)
      expect(event.exited?).to be(false)
    end
  ensure
    begin
      tracee&.detach
    rescue Ptrace::Error, Errno::ESRCH
      nil
    end

    begin
      Process.kill("KILL", child_pid) if child_pid
    rescue Errno::ESRCH
      nil
    end

    begin
      Process.wait(child_pid) if child_pid
    rescue Errno::ECHILD
      nil
    end
  end

  it "yields syscall enter/exit events via Ptrace.strace" do
    with_ptrace_permission do
      events = []

      Ptrace.strace("/bin/true") do |event|
        events << event
      end

      expect(events).not_to be_empty
      expect(events.any?(&:enter?)).to be(true)
      expect(events.any?(&:exit?)).to be(true)
    end
  end

  it "follows child process syscalls with follow_children mode" do
    with_ptrace_permission do
      script = "pid = fork { sleep 0.02 }; Process.wait(pid)"
      pids = []

      Ptrace.strace(RbConfig.ruby, "-e", script, follow_children: true) do |event|
        next unless event.enter?

        pids << event.tracee.pid
      end

      expect(pids.uniq.size).to be >= 2
    end
  end
end

# frozen_string_literal: true

RSpec.describe Ptrace::Event do
  describe "state helpers" do
    it "detects exited status and exit code" do
      event = described_class.new(100, 42 << 8)

      expect(event.exited?).to be(true)
      expect(event.exit_status).to eq(42)
      expect(event.signaled?).to be(false)
      expect(event.stopped?).to be(false)
    end

    it "detects signal stop and syscall stop" do
      trap_signal = Signal.list.fetch("TRAP")
      status = 0x7F | ((trap_signal | 0x80) << 8)
      event = described_class.new(200, status)

      expect(event.stopped?).to be(true)
      expect(event.stop_signal).to eq(trap_signal | 0x80)
      expect(event.syscall_stop?).to be(true)
    end

    it "detects ptrace event code" do
      status = 0x7F | (Signal.list.fetch("TRAP") << 8) | (Ptrace::Constants::PTRACE_EVENT_EXEC << 16)
      event = described_class.new(300, status)

      expect(event.exec_event?).to be(true)
      expect(event.fork_event?).to be(false)
      expect(event.clone_event?).to be(false)
      expect(event.vfork_event?).to be(false)
      expect(event.vfork_done_event?).to be(false)
      expect(event.exit_event?).to be(false)
    end

    it "detects vfork and vfork_done event codes" do
      vfork_status = 0x7F | (Signal.list.fetch("TRAP") << 8) | (Ptrace::Constants::PTRACE_EVENT_VFORK << 16)
      vfork_done_status = 0x7F | (Signal.list.fetch("TRAP") << 8) | (Ptrace::Constants::PTRACE_EVENT_VFORK_DONE << 16)

      vfork_event = described_class.new(301, vfork_status)
      vfork_done_event = described_class.new(302, vfork_done_status)

      expect(vfork_event.vfork_event?).to be(true)
      expect(vfork_done_event.vfork_done_event?).to be(true)
    end

    it "detects continued state" do
      event = described_class.new(301, 0xFFFF)

      expect(event.continued?).to be(true)
      expect(event.exited?).to be(false)
      expect(event.stopped?).to be(false)
    end

    it "detects signaled state and term signal" do
      event = described_class.new(302, 9)

      expect(event.signaled?).to be(true)
      expect(event.term_signal).to eq(9)
      expect(event.exited?).to be(false)
    end

    it "formats inspect output with exited summary" do
      event = described_class.new(999, 42 << 8)

      expect(event.inspect).to include("pid=999")
      expect(event.inspect).to include("status=0x2a00")
      expect(event.inspect).to include("state=exited(42)")
    end

    it "formats inspect output with syscall stop summary" do
      trap_signal = Signal.list.fetch("TRAP")
      status = 0x7F | ((trap_signal | 0x80) << 8)
      event = described_class.new(1001, status)

      expect(event.inspect).to include("state=syscall_stop")
    end

    it "formats inspect output with ptrace event name when present" do
      status = 0x7F | (Signal.list.fetch("TRAP") << 8) | (Ptrace::Constants::PTRACE_EVENT_EXEC << 16)
      event = described_class.new(1002, status)

      expect(event.inspect).to include("state=stopped(SIGTRAP)")
      expect(event.inspect).to include("event=exec")
    end

    it "formats inspect output for non-syscall stop without ptrace event name" do
      status = 0x7F | (Signal.list.fetch("STOP") << 8)
      event = described_class.new(1003, status)

      expect(event.inspect).to include("state=stopped(SIGSTOP)")
      expect(event.inspect).not_to include("event=")
    end

    it "formats inspect output for signaled state and falls back on unknown signal name" do
      event = described_class.new(1004, 9)
      allow(Signal).to receive(:signame).and_raise(ArgumentError)

      expect(event.inspect).to include("state=signaled(SIG9)")
    end

  end
end

# frozen_string_literal: true

RSpec.describe Ptrace::Permission do
  describe ".ptrace_scope" do
    it "returns parsed yama ptrace_scope when readable" do
      allow(File).to receive(:readable?).with(Ptrace::Permission::YAMA_PTRACE_SCOPE_PATH).and_return(true)
      allow(File).to receive(:read).with(Ptrace::Permission::YAMA_PTRACE_SCOPE_PATH).and_return("1\n")

      expect(described_class.ptrace_scope).to eq(1)
    end

    it "returns nil when ptrace_scope path is unavailable" do
      allow(File).to receive(:readable?).with(Ptrace::Permission::YAMA_PTRACE_SCOPE_PATH).and_return(false)

      expect(described_class.ptrace_scope).to be_nil
    end
  end

  describe ".effective_capabilities_mask" do
    it "reads CapEff from /proc/self/status" do
      allow(File).to receive(:readable?).with(Ptrace::Permission::PROC_STATUS_PATH).and_return(true)
      allow(File).to receive(:read).with(Ptrace::Permission::PROC_STATUS_PATH).and_return("Name:\truby\nCapEff:\t0000000000000200\n")

      expect(described_class.effective_capabilities_mask).to eq(0x200)
    end

    it "returns nil when CapEff line is missing" do
      allow(File).to receive(:readable?).with(Ptrace::Permission::PROC_STATUS_PATH).and_return(true)
      allow(File).to receive(:read).with(Ptrace::Permission::PROC_STATUS_PATH).and_return("Name:\truby\n")

      expect(described_class.effective_capabilities_mask).to be_nil
    end
  end

  describe ".cap_sys_ptrace?" do
    it "returns true when CAP_SYS_PTRACE bit is present" do
      allow(described_class).to receive(:effective_capabilities_mask).and_return(1 << Ptrace::Permission::CAP_SYS_PTRACE_BIT)

      expect(described_class.cap_sys_ptrace?).to be(true)
    end

    it "returns false when capabilities cannot be read" do
      allow(described_class).to receive(:effective_capabilities_mask).and_return(nil)

      expect(described_class.cap_sys_ptrace?).to be(false)
    end
  end

  describe ".diagnostics" do
    it "adds guidance when not privileged and ptrace_scope is strict" do
      allow(Process).to receive(:uid).and_return(1000)
      allow(Process).to receive(:euid).and_return(1000)
      allow(described_class).to receive(:cap_sys_ptrace?).and_return(false)
      allow(described_class).to receive(:ptrace_scope).and_return(2)

      diagnostics = described_class.diagnostics

      expect(diagnostics[:ptrace_privileged]).to be(false)
      expect(diagnostics[:cap_sys_ptrace]).to be(false)
      expect(diagnostics[:yama_ptrace_scope]).to eq(2)
      expect(diagnostics[:hints]).to include("run as root or grant CAP_SYS_PTRACE")
      expect(diagnostics[:hints]).to include("set /proc/sys/kernel/yama/ptrace_scope to 0 or 1")
    end

    it "returns no hints when privileged and yama is permissive" do
      allow(Process).to receive(:uid).and_return(0)
      allow(Process).to receive(:euid).and_return(0)
      allow(described_class).to receive(:cap_sys_ptrace?).and_return(true)
      allow(described_class).to receive(:ptrace_scope).and_return(0)

      diagnostics = described_class.diagnostics

      expect(diagnostics[:ptrace_privileged]).to be(true)
      expect(diagnostics[:hints]).to eq([])
    end
  end
end

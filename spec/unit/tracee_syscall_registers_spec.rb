# frozen_string_literal: true

RSpec.describe Rptrace::Tracee do
  let(:tracee) { described_class.allocate }
  let(:registers) { instance_double(Rptrace::Registers) }

  before do
    tracee.instance_variable_set(:@pid, 12_345)
    tracee.instance_variable_set(:@registers, registers)
    tracee.instance_variable_set(:@memory, instance_double(Rptrace::Memory))
  end

  describe "#current_syscall" do
    it "uses x86_64 syscall register layout" do
      allow(registers).to receive(:[]).with(:orig_rax).and_return(1)

      info = tracee.current_syscall(arch: :x86_64)

      expect(info.name).to eq(:write)
      expect(info.number).to eq(1)
    end

    it "uses aarch64 syscall register layout" do
      allow(registers).to receive(:[]).with(:x8).and_return(64)

      info = tracee.current_syscall(arch: :aarch64)

      expect(info.name).to eq(:write)
      expect(info.number).to eq(64)
    end
  end

  describe "#syscall_args" do
    it "returns x86_64 argument registers in order" do
      allow(registers).to receive(:[]).with(:rdi).and_return(1)
      allow(registers).to receive(:[]).with(:rsi).and_return(2)
      allow(registers).to receive(:[]).with(:rdx).and_return(3)
      allow(registers).to receive(:[]).with(:r10).and_return(4)
      allow(registers).to receive(:[]).with(:r8).and_return(5)
      allow(registers).to receive(:[]).with(:r9).and_return(6)

      expect(tracee.syscall_args(arch: :x86_64)).to eq([1, 2, 3, 4, 5, 6])
    end

    it "returns aarch64 argument registers in order" do
      allow(registers).to receive(:[]).with(:x0).and_return(11)
      allow(registers).to receive(:[]).with(:x1).and_return(12)
      allow(registers).to receive(:[]).with(:x2).and_return(13)
      allow(registers).to receive(:[]).with(:x3).and_return(14)
      allow(registers).to receive(:[]).with(:x4).and_return(15)
      allow(registers).to receive(:[]).with(:x5).and_return(16)

      expect(tracee.syscall_args(arch: :aarch64)).to eq([11, 12, 13, 14, 15, 16])
    end
  end

  describe "#syscall_return" do
    it "returns x86_64 return register" do
      allow(registers).to receive(:[]).with(:rax).and_return(-2)

      expect(tracee.syscall_return(arch: :x86_64)).to eq(-2)
    end

    it "returns aarch64 return register" do
      allow(registers).to receive(:[]).with(:x0).and_return(-2)

      expect(tracee.syscall_return(arch: :aarch64)).to eq(-2)
    end
  end
end

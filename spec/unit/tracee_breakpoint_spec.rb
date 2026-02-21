# frozen_string_literal: true

RSpec.describe Ptrace::Tracee do
  let(:tracee) { described_class.allocate }
  let(:memory) { instance_double(Ptrace::Memory) }
  let(:registers) { instance_double(Ptrace::Registers) }

  before do
    tracee.instance_variable_set(:@pid, 4321)
    tracee.instance_variable_set(:@registers, registers)
    tracee.instance_variable_set(:@memory, memory)
  end

  describe "software breakpoints" do
    before do
      allow(Ptrace::CStructs).to receive(:arch).and_return(:x86_64)
    end

    it "installs an INT3 opcode and stores original byte" do
      expect(memory).to receive(:read).with(0x401000, 1).and_return("\x55".b)
      expect(memory).to receive(:write).with(0x401000, "\xCC".b)

      breakpoint = tracee.set_breakpoint(0x401000)

      expect(breakpoint).to be_a(Ptrace::Breakpoint)
      expect(breakpoint.address).to eq(0x401000)
      expect(breakpoint.original_byte).to eq("\x55".b)
      expect(tracee.breakpoint(0x401000)).to eq(breakpoint)
      expect(tracee.breakpoints).to contain_exactly(breakpoint)
    end

    it "reuses existing enabled breakpoint without touching memory" do
      existing = Ptrace::Breakpoint.new(tracee: tracee, address: 0x401000, original_byte: "\x90".b)
      tracee.instance_variable_set(:@breakpoint_store, {0x401000 => existing})

      expect(memory).not_to receive(:read)
      expect(memory).not_to receive(:write)

      expect(tracee.set_breakpoint(0x401000)).to eq(existing)
    end

    it "restores original byte when removing breakpoint" do
      breakpoint = Ptrace::Breakpoint.new(tracee: tracee, address: 0x401000, original_byte: "\x55".b)
      tracee.instance_variable_set(:@breakpoint_store, {0x401000 => breakpoint})
      expect(memory).to receive(:write).with(0x401000, "\x55".b)

      removed = tracee.remove_breakpoint(0x401000)

      expect(removed).to eq(breakpoint)
      expect(removed.enabled?).to be(false)
      expect(tracee.breakpoints).to be_empty
    end

    it "returns nil when removing unknown breakpoint" do
      expect(memory).not_to receive(:write)

      expect(tracee.remove_breakpoint(0x401000)).to be_nil
    end

    it "clears all active breakpoints and returns count" do
      bp1 = Ptrace::Breakpoint.new(tracee: tracee, address: 0x401000, original_byte: "\x55".b)
      bp2 = Ptrace::Breakpoint.new(tracee: tracee, address: 0x402000, original_byte: "\x48".b)
      tracee.instance_variable_set(:@breakpoint_store, {0x401000 => bp1, 0x402000 => bp2})
      expect(memory).to receive(:write).with(0x401000, "\x55".b)
      expect(memory).to receive(:write).with(0x402000, "\x48".b)

      expect(tracee.clear_breakpoints).to eq(2)
      expect(tracee.breakpoints).to be_empty
    end

    it "looks up breakpoints by integerized address" do
      breakpoint = Ptrace::Breakpoint.new(tracee: tracee, address: 0x401000, original_byte: "\x90".b)
      tracee.instance_variable_set(:@breakpoint_store, {0x401000 => breakpoint})

      expect(tracee.breakpoint("4198400")).to eq(breakpoint)
    end

    it "detects current breakpoint hit at rip - 1" do
      breakpoint = Ptrace::Breakpoint.new(tracee: tracee, address: 0x401000, original_byte: "\x90".b)
      tracee.instance_variable_set(:@breakpoint_store, {0x401000 => breakpoint})
      allow(registers).to receive(:[]).with(:rip).and_return(0x401001)

      expect(tracee.breakpoint_hit?).to be(true)
      expect(tracee.current_breakpoint).to eq(breakpoint)
    end

    it "returns false for breakpoint_hit? when rip is not on known trap site" do
      tracee.instance_variable_set(:@breakpoint_store, {0x401000 => Ptrace::Breakpoint.new(tracee: tracee, address: 0x401000, original_byte: "\x90".b)})
      allow(registers).to receive(:[]).with(:rip).and_return(0x500000)

      expect(tracee.breakpoint_hit?).to be(false)
      expect(tracee.current_breakpoint).to be_nil
    end

    it "steps over a currently hit breakpoint and reinstalls it" do
      breakpoint = Ptrace::Breakpoint.new(tracee: tracee, address: 0x401000, original_byte: "\x55".b)
      tracee.instance_variable_set(:@breakpoint_store, {0x401000 => breakpoint})
      allow(registers).to receive(:[]).with(:rip).and_return(0x401001)
      expect(memory).to receive(:write).with(0x401000, "\x55".b).ordered
      expect(registers).to receive(:write).with(rip: 0x401000).ordered
      expect(Ptrace::Binding).to receive(:safe_ptrace).with(Ptrace::Constants::PTRACE_SINGLESTEP, 4321, 0, 0).ordered
      allow(Ptrace::Binding).to receive(:safe_waitpid).with(4321, flags: Ptrace::Constants::WALL).and_return([4321, 0x57F])
      expect(memory).to receive(:write).with(0x401000, "\xCC".b).ordered

      event = tracee.step_over_breakpoint

      expect(event).to be_a(Ptrace::Event)
      expect(event.pid).to eq(4321)
    end

    it "raises when stepping over without a current breakpoint hit" do
      allow(registers).to receive(:[]).with(:rip).and_return(0x500000)

      expect do
        tracee.step_over_breakpoint
      end.to raise_error(Ptrace::Error, /no active breakpoint/)
    end
  end

  it "rejects software breakpoint install on non-x86_64 architecture" do
    allow(Ptrace::CStructs).to receive(:arch).and_return(:aarch64)

    expect(memory).not_to receive(:read)
    expect(memory).not_to receive(:write)
    expect do
      tracee.set_breakpoint(0x401000)
    end.to raise_error(Ptrace::UnsupportedArchError, /supported only on x86_64/)
  end

  it "returns no current breakpoint on non-x86_64 architecture" do
    allow(registers).to receive(:[]).with(:pc).and_return(0x1001)
    expect(tracee.current_breakpoint(arch: :aarch64)).to be_nil
  end

  it "rejects step_over_breakpoint on non-x86_64 architecture" do
    allow(Ptrace::CStructs).to receive(:arch).and_return(:aarch64)

    expect do
      tracee.step_over_breakpoint
    end.to raise_error(Ptrace::UnsupportedArchError, /supported only on x86_64/)
  end
end

# frozen_string_literal: true

RSpec.describe Rptrace::Breakpoint do
  let(:tracee) { instance_double(Rptrace::Tracee) }

  it "stores address and original byte" do
    breakpoint = described_class.new(tracee: tracee, address: 0x401000, original_byte: "\x55".b)

    expect(breakpoint.address).to eq(0x401000)
    expect(breakpoint.original_byte).to eq("\x55".b)
    expect(breakpoint.enabled?).to be(true)
  end

  it "requires one-byte original opcode" do
    expect do
      described_class.new(tracee: tracee, address: 0x401000, original_byte: "\x90\x90".b)
    end.to raise_error(ArgumentError, /exactly one byte/)
  end

  it "disables breakpoint state" do
    breakpoint = described_class.new(tracee: tracee, address: 0x401000, original_byte: "\x55".b)

    expect(breakpoint.disable!).to eq(breakpoint)
    expect(breakpoint.enabled?).to be(false)
  end

  it "delegates restore to tracee" do
    breakpoint = described_class.new(tracee: tracee, address: 0x401000, original_byte: "\x55".b)
    expect(tracee).to receive(:remove_breakpoint).with(0x401000).and_return(:restored)

    expect(breakpoint.restore).to eq(:restored)
  end

  it "includes address and state in inspect" do
    breakpoint = described_class.new(tracee: tracee, address: 0x401000, original_byte: "\x55".b)
    breakpoint.disable!

    expect(breakpoint.inspect).to include("addr=0x401000")
    expect(breakpoint.inspect).to include("state=disabled")
  end
end

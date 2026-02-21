# frozen_string_literal: true

RSpec.describe Ptrace::CStructs do
  it "supports host architecture" do
    expect(%i[x86_64 aarch64]).to include(described_class.arch)
  end

  it "calculates register struct size from register count" do
    names = described_class.reg_names(arch: described_class.arch)

    expect(described_class.regs_size(arch: described_class.arch)).to eq(names.length * 8)
  end

  it "packs and unpacks iovec structures" do
    encoded = described_class.pack_iovec(base: 0x1234, length: 216)
    decoded = described_class.unpack_iovec(encoded)

    expect(decoded[:base]).to eq(0x1234)
    expect(decoded[:length]).to eq(216)
  end

  it "raises for unsupported register architecture" do
    expect do
      described_class.reg_names(arch: :mips)
    end.to raise_error(Ptrace::UnsupportedArchError, /Unsupported architecture/)
  end
end

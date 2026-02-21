# frozen_string_literal: true

RSpec.describe Rptrace::CStructs do
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

  it "packs and unpacks seccomp metadata structures" do
    encoded = described_class.pack_seccomp_metadata(filter_off: 3, flags: 0x40)
    decoded = described_class.unpack_seccomp_metadata(encoded)

    expect(described_class.seccomp_metadata_size).to eq(16)
    expect(decoded).to eq(filter_off: 3, flags: 0x40)
  end

  it "decodes seccomp filter instructions" do
    bytes = [
      [0x20, 0, 0, 4].pack("S<CCL<"),
      [0x15, 0, 1, 0xC000003E].pack("S<CCL<")
    ].join

    decoded = described_class.decode_seccomp_filter(bytes)

    expect(decoded).to eq([
      { code: 0x20, jt: 0, jf: 0, k: 4 },
      { code: 0x15, jt: 0, jf: 1, k: 0xC000003E }
    ])
  end

  it "raises when seccomp filter bytes are not instruction-aligned" do
    expect do
      described_class.decode_seccomp_filter("\x00" * 7)
    end.to raise_error(ArgumentError, /align/)
  end

  it "raises for unsupported register architecture" do
    expect do
      described_class.reg_names(arch: :mips)
    end.to raise_error(Rptrace::UnsupportedArchError, /Unsupported architecture/)
  end
end

# frozen_string_literal: true

RSpec.describe Ptrace::CStructs do
  it "supports host architecture" do
    expect(%i[x86_64 aarch64]).to include(described_class.arch)
  end

  it "calculates register struct size from register count" do
    names = described_class.reg_names(arch: described_class.arch)

    expect(described_class.regs_size(arch: described_class.arch)).to eq(names.length * 8)
  end
end

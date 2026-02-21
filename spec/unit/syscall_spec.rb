# frozen_string_literal: true

RSpec.describe Rptrace::Syscall do
  describe ".from_number" do
    it "returns syscall info with argument template for known x86_64 syscall" do
      info = described_class.from_number(1, arch: :x86_64)

      expect(info.number).to eq(1)
      expect(info.name).to eq(:write)
      expect(info.arg_names).to eq(%i[fd buf count])
      expect(info.arg_types).to eq(%i[fd buf size])
    end

    it "returns fallback info for unknown syscall numbers" do
      info = described_class.from_number(99_999, arch: :x86_64)

      expect(info.name).to eq(:syscall_99999)
      expect(info.arg_names).to eq([])
      expect(info.arg_types).to eq([])
    end
  end

  describe ".from_name" do
    it "returns syscall info with number for known x86_64 name" do
      info = described_class.from_name(:openat, arch: :x86_64)

      expect(info.number).to eq(257)
      expect(info.arg_names).to eq(%i[dirfd pathname flags mode])
      expect(info.arg_types).to eq(%i[fd str flags mode])
    end

    it "returns nil for unknown names" do
      expect(described_class.from_name(:definitely_unknown_call, arch: :x86_64)).to be_nil
    end
  end

  describe ".table" do
    it "returns empty hash for unsupported architecture" do
      expect(described_class.table(arch: :mips)).to eq({})
      expect(described_class.by_name_table(arch: :mips)).to eq({})
    end
  end
end

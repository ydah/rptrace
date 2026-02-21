# frozen_string_literal: true

RSpec.describe Ptrace::ProcMaps do
  describe ".parse_line" do
    it "parses a file-backed mapping line" do
      line = "00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/bash"

      map = described_class.parse_line(line)

      expect(map.start_addr).to eq(0x00400000)
      expect(map.end_addr).to eq(0x00452000)
      expect(map.permissions).to eq("r-xp")
      expect(map.offset).to eq(0)
      expect(map.device).to eq("08:02")
      expect(map.inode).to eq(173_521)
      expect(map.pathname).to eq("/usr/bin/bash")
      expect(map.readable?).to be(true)
      expect(map.writable?).to be(false)
      expect(map.executable?).to be(true)
      expect(map.private?).to be(true)
      expect(map.shared?).to be(false)
      expect(map.anonymous?).to be(false)
      expect(map.size).to eq(0x52000)
    end

    it "parses an anonymous mapping line" do
      line = "7f9d3f5f7000-7f9d3f5fa000 rw-p 00000000 00:00 0"

      map = described_class.parse_line(line)

      expect(map.pathname).to be_nil
      expect(map.anonymous?).to be(true)
      expect(map.writable?).to be(true)
      expect(map.private?).to be(true)
    end

    it "preserves path labels containing spaces" do
      line = "7f9d3f5fa000-7f9d3f600000 r--s 00000000 08:02 12345 /tmp/a mapped file"

      map = described_class.parse_line(line)

      expect(map.pathname).to eq("/tmp/a mapped file")
      expect(map.shared?).to be(true)
    end

    it "raises for malformed input" do
      expect do
        described_class.parse_line("not a proc maps row")
      end.to raise_error(ArgumentError, /invalid \/proc maps line/)
    end
  end

  describe ".parse" do
    it "parses all non-empty lines" do
      content = <<~MAPS
        00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/bash

        00652000-00653000 r--p 00052000 08:02 173521 /usr/bin/bash
      MAPS

      maps = described_class.parse(content)

      expect(maps.size).to eq(2)
      expect(maps.map(&:offset)).to eq([0, 0x52000])
    end
  end

  describe ".read" do
    it "reads and parses /proc/<pid>/maps" do
      allow(File).to receive(:read).with("/proc/42/maps").and_return(
        "00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/bash\n"
      )

      maps = described_class.read(42)

      expect(maps.size).to eq(1)
      expect(maps.first.pathname).to eq("/usr/bin/bash")
    end
  end
end

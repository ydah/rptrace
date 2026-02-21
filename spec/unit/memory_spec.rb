# frozen_string_literal: true

RSpec.describe Ptrace::Memory do
  let(:tracee) { instance_double(Ptrace::Tracee, pid: 4321) }
  let(:memory) { described_class.new(tracee) }
  let(:word_size) { described_class::WORD_SIZE }
  let(:pack_format) { word_size == 8 ? "Q<" : "L<" }
  let(:word_mask) { (1 << (word_size * 8)) - 1 }

  let(:to_word) do
    lambda do |string|
      string.b.byteslice(0, word_size).ljust(word_size, "\x00").unpack1(pack_format)
    end
  end
  let(:from_word) do
    lambda do |value|
      [Integer(value) & word_mask].pack(pack_format)
    end
  end

  it "reads unaligned bytes across word boundaries" do
    skip "64-bit only" unless word_size == 8

    words = {
      0x1000 => to_word.call("ABCDEFGH"),
      0x1008 => to_word.call("IJKLMNOP")
    }

    allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, _pid, addr, data|
      case request
      when Ptrace::Constants::PTRACE_PEEKDATA
        words.fetch(addr)
      when Ptrace::Constants::PTRACE_POKEDATA
        words[addr] = Integer(data)
        0
      else
        raise "unexpected request: #{request}"
      end
    end

    expect(memory.read(0x1003, 10)).to eq("DEFGHIJKLM".b)
  end

  it "writes bytes while preserving untouched bytes in edge words" do
    skip "64-bit only" unless word_size == 8

    words = {
      0x3000 => to_word.call("ABCDEFGH"),
      0x3008 => to_word.call("IJKLMNOP")
    }

    allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, _pid, addr, data|
      case request
      when Ptrace::Constants::PTRACE_PEEKDATA
        words.fetch(addr)
      when Ptrace::Constants::PTRACE_POKEDATA
        words[addr] = Integer(data)
        0
      else
        raise "unexpected request: #{request}"
      end
    end

    written = memory.write(0x3003, "xyz12345")

    expect(written).to eq(8)
    expect(from_word.call(words[0x3000])).to eq("ABCxyz12")
    expect(from_word.call(words[0x3008])).to eq("345LMNOP")
  end

  it "reads nul terminated string" do
    words = {
      0x4000 => to_word.call("hello\x00zz"),
      0x4000 + word_size => to_word.call("rest")
    }

    allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, _pid, addr, data|
      case request
      when Ptrace::Constants::PTRACE_PEEKDATA
        words.fetch(addr)
      when Ptrace::Constants::PTRACE_POKEDATA
        words[addr] = Integer(data)
        0
      else
        raise "unexpected request: #{request}"
      end
    end

    expect(memory.read_string(0x4000, max: word_size * 2)).to eq("hello".b)
  end

  it "returns zero when writing empty bytes" do
    expect(memory.write(0x1000, "")).to eq(0)
  end
end

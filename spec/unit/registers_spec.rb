# frozen_string_literal: true

require "fiddle"

RSpec.describe Ptrace::Registers do
  let(:tracee) { instance_double(Ptrace::Tracee, pid: 1234) }
  let(:registers) { described_class.new(tracee) }
  let(:reg_names) { Ptrace::CStructs.reg_names }
  let(:reg_a) { reg_names.fetch(0) }
  let(:reg_b) { reg_names.fetch(1) }
  let(:initial_values) do
    reg_names.each_with_index.each_with_object({}) do |(name, index), hash|
      hash[name] = index + 1
    end
  end
  let(:encoded_initial) { Ptrace::CStructs.encode_regs(initial_values) }

  it "reads registers through PTRACE_GETREGS" do
    allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, _pid, _addr, data|
      case request
      when Ptrace::Constants::PTRACE_GETREGS
        ptr = Fiddle::Pointer.new(data)
        ptr[0, encoded_initial.bytesize] = encoded_initial
        0
      else
        raise "unexpected request: #{request}"
      end
    end

    expect(registers.read).to eq(initial_values)
  end

  it "writes merged registers through PTRACE_SETREGS" do
    written = nil

    allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, _pid, _addr, data|
      case request
      when Ptrace::Constants::PTRACE_GETREGS
        ptr = Fiddle::Pointer.new(data)
        ptr[0, encoded_initial.bytesize] = encoded_initial
        0
      when Ptrace::Constants::PTRACE_SETREGS
        written = Fiddle::Pointer.new(data)[0, encoded_initial.bytesize]
        0
      else
        raise "unexpected request: #{request}"
      end
    end

    merged = registers.write(reg_a => 42, reg_b => 0x401000)
    decoded = Ptrace::CStructs.decode_regs(written)

    expect(merged[reg_a]).to eq(42)
    expect(merged[reg_b]).to eq(0x401000)
    expect(decoded[reg_a]).to eq(42)
    expect(decoded[reg_b]).to eq(0x401000)
    expect(decoded.fetch(reg_names.fetch(2))).to eq(initial_values.fetch(reg_names.fetch(2)))
  end

  it "supports getter/setter accessors for known register names" do
    written = nil

    allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, _pid, _addr, data|
      case request
      when Ptrace::Constants::PTRACE_GETREGS
        ptr = Fiddle::Pointer.new(data)
        ptr[0, encoded_initial.bytesize] = encoded_initial
        0
      when Ptrace::Constants::PTRACE_SETREGS
        written = Fiddle::Pointer.new(data)[0, encoded_initial.bytesize]
        0
      else
        raise "unexpected request: #{request}"
      end
    end

    expect(registers.public_send(reg_a)).to eq(initial_values[reg_a])

    registers.public_send(:"#{reg_a}=", 99)
    decoded = Ptrace::CStructs.decode_regs(written)

    expect(decoded[reg_a]).to eq(99)
  end

  it "raises for unknown registers" do
    expect { registers[:unknown] }.to raise_error(KeyError)
    expect { registers.write(unknown: 1) }.to raise_error(KeyError)
    expect { registers.unknown }.to raise_error(NoMethodError)
  end
end

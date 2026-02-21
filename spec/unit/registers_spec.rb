# frozen_string_literal: true

require "fiddle"

RSpec.describe Ptrace::Registers do
  def iovec_size
    Ptrace::CStructs::POINTER_SIZE * 2
  end

  def write_reg_buffer_from_ptr(data, encoded)
    if arch == :aarch64
      iovec_bytes = Fiddle::Pointer.new(data)[0, iovec_size]
      decoded = Ptrace::CStructs.unpack_iovec(iovec_bytes)
      Fiddle::Pointer.new(decoded.fetch(:base))[0, encoded.bytesize] = encoded
    else
      Fiddle::Pointer.new(data)[0, encoded.bytesize] = encoded
    end
  end

  def extract_written_buffer(data, size)
    if arch == :aarch64
      iovec_bytes = Fiddle::Pointer.new(data)[0, iovec_size]
      decoded = Ptrace::CStructs.unpack_iovec(iovec_bytes)
      Fiddle::Pointer.new(decoded.fetch(:base))[0, size]
    else
      Fiddle::Pointer.new(data)[0, size]
    end
  end

  let(:tracee) { instance_double(Ptrace::Tracee, pid: 1234) }
  let(:arch) { Ptrace::CStructs.arch }
  let(:registers) { described_class.new(tracee, arch: arch) }
  let(:reg_names) { Ptrace::CStructs.reg_names(arch: arch) }
  let(:reg_a) { reg_names.fetch(0) }
  let(:reg_b) { reg_names.fetch(1) }
  let(:read_request) { arch == :aarch64 ? Ptrace::Constants::PTRACE_GETREGSET : Ptrace::Constants::PTRACE_GETREGS }
  let(:write_request) { arch == :aarch64 ? Ptrace::Constants::PTRACE_SETREGSET : Ptrace::Constants::PTRACE_SETREGS }
  let(:initial_values) do
    reg_names.each_with_index.each_with_object({}) do |(name, index), hash|
      hash[name] = index + 1
    end
  end
  let(:encoded_initial) { Ptrace::CStructs.encode_regs(initial_values, arch: arch) }

  it "reads registers through ptrace register request" do
    allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, _pid, addr, data|
      case request
      when read_request
        expect(addr).to eq(Ptrace::Constants::NT_PRSTATUS) if arch == :aarch64
        write_reg_buffer_from_ptr(data, encoded_initial)
        0
      else
        raise "unexpected request: #{request}"
      end
    end

    expect(registers.read).to eq(initial_values)
  end

  it "writes merged registers through ptrace register request" do
    written = nil

    allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, _pid, addr, data|
      case request
      when read_request
        expect(addr).to eq(Ptrace::Constants::NT_PRSTATUS) if arch == :aarch64
        write_reg_buffer_from_ptr(data, encoded_initial)
        0
      when write_request
        expect(addr).to eq(Ptrace::Constants::NT_PRSTATUS) if arch == :aarch64
        written = extract_written_buffer(data, encoded_initial.bytesize)
        0
      else
        raise "unexpected request: #{request}"
      end
    end

    merged = registers.write(reg_a => 42, reg_b => 0x401000)
    decoded = Ptrace::CStructs.decode_regs(written, arch: arch)

    expect(merged[reg_a]).to eq(42)
    expect(merged[reg_b]).to eq(0x401000)
    expect(decoded[reg_a]).to eq(42)
    expect(decoded[reg_b]).to eq(0x401000)
    expect(decoded.fetch(reg_names.fetch(2))).to eq(initial_values.fetch(reg_names.fetch(2)))
  end

  it "supports getter/setter accessors for known register names" do
    written = nil

    allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, _pid, addr, data|
      case request
      when read_request
        expect(addr).to eq(Ptrace::Constants::NT_PRSTATUS) if arch == :aarch64
        write_reg_buffer_from_ptr(data, encoded_initial)
        0
      when write_request
        expect(addr).to eq(Ptrace::Constants::NT_PRSTATUS) if arch == :aarch64
        written = extract_written_buffer(data, encoded_initial.bytesize)
        0
      else
        raise "unexpected request: #{request}"
      end
    end

    expect(registers.public_send(reg_a)).to eq(initial_values[reg_a])

    registers.public_send(:"#{reg_a}=", 99)
    decoded = Ptrace::CStructs.decode_regs(written, arch: arch)

    expect(decoded[reg_a]).to eq(99)
  end

  it "raises for unknown registers" do
    expect { registers[:unknown] }.to raise_error(KeyError)
    expect { registers.write(unknown: 1) }.to raise_error(KeyError)
    expect { registers.unknown }.to raise_error(NoMethodError)
  end
end

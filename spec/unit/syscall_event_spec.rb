# frozen_string_literal: true

RSpec.describe Ptrace::SyscallEvent do
  let(:memory) { instance_double(Ptrace::Memory) }
  let(:tracee) { instance_double(Ptrace::Tracee, memory: memory) }

  describe "#to_s" do
    it "formats enter event with decoded string pointer arguments" do
      syscall = Ptrace::Syscall::SyscallInfo.new(
        number: 257,
        name: :openat,
        arg_names: %i[dirfd pathname flags mode],
        arg_types: %i[fd str flags mode]
      )
      allow(memory).to receive(:read_string).with(0x1000).and_return("/tmp/file")

      event = described_class.new(
        tracee: tracee,
        syscall: syscall,
        args: [-100, 0x1000, 0x241, 0o644],
        phase: :enter
      )

      expect(event.to_s).to eq("openat(-100, \"/tmp/file\", 0x241, 420) ...")
    end

    it "formats syscall errors like strace" do
      syscall = Ptrace::Syscall::SyscallInfo.new(
        number: 2,
        name: :open,
        arg_names: %i[pathname flags mode],
        arg_types: %i[str flags mode]
      )
      allow(memory).to receive(:read_string).with(0x5000).and_return("/does/not/exist")

      event = described_class.new(
        tracee: tracee,
        syscall: syscall,
        args: [0x5000, 0, 0],
        phase: :exit,
        return_value: -Errno::ENOENT::Errno
      )

      expect(event.to_s).to eq("open(\"/does/not/exist\", 0x0, 0) = -1 ENOENT (No such file or directory)")
    end

    it "falls back to pointer output when reading string fails" do
      syscall = Ptrace::Syscall::SyscallInfo.new(
        number: 59,
        name: :execve,
        arg_names: %i[filename argv envp],
        arg_types: %i[str ptr ptr]
      )
      allow(memory).to receive(:read_string).with(0x7000).and_raise(Ptrace::Error.new("failed"))

      event = described_class.new(
        tracee: tracee,
        syscall: syscall,
        args: [0x7000, 0, 0],
        phase: :enter
      )

      expect(event.to_s).to eq("execve(0x7000, NULL, NULL) ...")
    end
  end
end

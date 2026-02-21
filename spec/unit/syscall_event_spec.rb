# frozen_string_literal: true

require "fcntl"

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
        args: [-100, 0x1000, Fcntl::O_WRONLY | Fcntl::O_CREAT, 0o644],
        phase: :enter
      )

      rendered = event.to_s
      expect(rendered).to include("openat(-100, \"/tmp/file\",")
      expect(rendered).to include("O_WRONLY")
      expect(rendered).to include("O_CREAT")
      expect(rendered).to end_with(", 0644) ...")
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

      expect(event.to_s).to eq("open(\"/does/not/exist\", O_RDONLY, 0) = -1 ENOENT (No such file or directory)")
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

    it "formats normal numeric return values" do
      syscall = Ptrace::Syscall::SyscallInfo.new(number: 0, name: :read, arg_names: %i[fd], arg_types: %i[fd])
      event = described_class.new(tracee: tracee, syscall: syscall, args: [3], phase: :exit, return_value: 12)

      expect(event.to_s).to eq("read(3) = 12")
    end

    it "formats nil return as unknown marker" do
      syscall = Ptrace::Syscall::SyscallInfo.new(number: 60, name: :exit, arg_names: %i[status], arg_types: %i[int])
      event = described_class.new(tracee: tracee, syscall: syscall, args: [0], phase: :exit, return_value: nil)

      expect(event.to_s).to eq("exit(0) = ?")
    end

    it "formats non-pointer/non-integer values with inspect fallback" do
      syscall = Ptrace::Syscall::SyscallInfo.new(number: 999, name: :custom, arg_names: [:obj], arg_types: [:unknown])
      event = described_class.new(tracee: tracee, syscall: syscall, args: [%w[a b]], phase: :enter)

      expect(event.to_s).to eq("custom([\"a\", \"b\"]) ...")
    end

    it "keeps non-open flags as hex" do
      syscall = Ptrace::Syscall::SyscallInfo.new(
        number: 16,
        name: :ioctl,
        arg_names: %i[fd request argp],
        arg_types: %i[fd flags ptr]
      )
      event = described_class.new(tracee: tracee, syscall: syscall, args: [3, 0x1234, 0], phase: :enter)

      expect(event.to_s).to eq("ioctl(3, 0x1234, NULL) ...")
    end
  end
end

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

    it "decodes mmap prot and flags as symbolic names" do
      stub_const("#{described_class}::PROT_NAMES", {0 => "PROT_NONE", 1 => "PROT_READ", 2 => "PROT_WRITE"})
      stub_const("#{described_class}::MAP_TYPE_MASK", 0x0f)
      stub_const("#{described_class}::MAP_TYPE_NAMES", {1 => "MAP_SHARED", 2 => "MAP_PRIVATE"})
      stub_const("#{described_class}::MAP_FLAG_NAMES", {0x20 => "MAP_ANONYMOUS"})

      syscall = Ptrace::Syscall::SyscallInfo.new(
        number: 9,
        name: :mmap,
        arg_names: %i[addr length prot flags fd offset],
        arg_types: %i[ptr size flags flags fd int]
      )
      event = described_class.new(
        tracee: tracee,
        syscall: syscall,
        args: [0, 4096, 1 | 2, 2 | 0x20, -1, 0],
        phase: :enter
      )

      rendered = event.to_s
      expect(rendered).to include("PROT_READ")
      expect(rendered).to include("PROT_WRITE")
      expect(rendered).to include("MAP_PRIVATE")
      expect(rendered).to include("MAP_ANONYMOUS")
    end

    it "shows unknown mmap bits as hex residue" do
      stub_const("#{described_class}::PROT_NAMES", {1 => "PROT_READ"})
      stub_const("#{described_class}::MAP_TYPE_MASK", 0x0f)
      stub_const("#{described_class}::MAP_TYPE_NAMES", {1 => "MAP_SHARED", 2 => "MAP_PRIVATE"})
      stub_const("#{described_class}::MAP_FLAG_NAMES", {0x20 => "MAP_ANONYMOUS"})

      syscall = Ptrace::Syscall::SyscallInfo.new(
        number: 9,
        name: :mmap,
        arg_names: %i[addr length prot flags fd offset],
        arg_types: %i[ptr size flags flags fd int]
      )
      unknown_prot = 0x40
      unknown_map_flag = 0x80

      event = described_class.new(
        tracee: tracee,
        syscall: syscall,
        args: [0, 4096, unknown_prot, unknown_map_flag, -1, 0],
        phase: :enter
      )

      rendered = event.to_s
      expect(rendered).to include("0x40")
      expect(rendered).to include("0x80")
    end

    it "decodes clone flags and exit signal names" do
      syscall = Ptrace::Syscall::SyscallInfo.new(
        number: 56,
        name: :clone,
        arg_names: %i[flags child_stack ptid ctid newtls],
        arg_types: %i[flags ptr ptr ptr ptr]
      )
      event = described_class.new(
        tracee: tracee,
        syscall: syscall,
        args: [0x0001_0000 | 0x0000_0100 | Signal.list.fetch("CHLD"), 0, 0, 0, 0],
        phase: :enter
      )

      rendered = event.to_s
      expect(rendered).to include("CLONE_THREAD")
      expect(rendered).to include("CLONE_VM")
      expect(rendered).to include("SIGCHLD")
    end

    it "shows unknown clone flag bits as hex residue" do
      syscall = Ptrace::Syscall::SyscallInfo.new(
        number: 56,
        name: :clone,
        arg_names: %i[flags child_stack ptid ctid newtls],
        arg_types: %i[flags ptr ptr ptr ptr]
      )
      event = described_class.new(
        tracee: tracee,
        syscall: syscall,
        args: [0x1_0000_0000, 0, 0, 0, 0],
        phase: :enter
      )

      expect(event.to_s).to include("0x100000000")
    end

    it "decodes wait4 option flags" do
      syscall = Ptrace::Syscall::SyscallInfo.new(
        number: 61,
        name: :wait4,
        arg_names: %i[pid stat_addr options rusage],
        arg_types: %i[pid ptr flags ptr]
      )
      event = described_class.new(
        tracee: tracee,
        syscall: syscall,
        args: [1234, 0, Ptrace::Constants::WNOHANG | Ptrace::Constants::WUNTRACED, 0],
        phase: :enter
      )

      rendered = event.to_s
      expect(rendered).to include("WNOHANG")
      expect(rendered).to include("WUNTRACED")
    end
  end
end

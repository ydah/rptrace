# frozen_string_literal: true

RSpec.describe Ptrace::Tracee do
  describe "instance controls" do
    let(:tracee) { described_class.allocate }

    before do
      tracee.instance_variable_set(:@pid, 4321)
      tracee.instance_variable_set(:@registers, instance_double(Ptrace::Registers))
      tracee.instance_variable_set(:@memory, instance_double(Ptrace::Memory))
    end

    it "sends CONT request and returns self" do
      expect(Ptrace::Binding).to receive(:safe_ptrace).with(Ptrace::Constants::PTRACE_CONT, 4321, 0, 9)
      expect(tracee.cont(signal: 9)).to eq(tracee)
    end

    it "sends SYSCALL request and returns self" do
      expect(Ptrace::Binding).to receive(:safe_ptrace).with(Ptrace::Constants::PTRACE_SYSCALL, 4321, 0, 0)
      expect(tracee.syscall).to eq(tracee)
    end

    it "sends SINGLESTEP request and returns self" do
      expect(Ptrace::Binding).to receive(:safe_ptrace).with(Ptrace::Constants::PTRACE_SINGLESTEP, 4321, 0, 2)
      expect(tracee.singlestep(signal: 2)).to eq(tracee)
    end

    it "sends INTERRUPT request and returns self" do
      expect(Ptrace::Binding).to receive(:safe_ptrace).with(Ptrace::Constants::PTRACE_INTERRUPT, 4321, 0, 0)
      expect(tracee.interrupt).to eq(tracee)
    end

    it "sends DETACH request and returns self" do
      expect(Ptrace::Binding).to receive(:safe_ptrace).with(Ptrace::Constants::PTRACE_DETACH, 4321, 0, 0)
      expect(tracee.detach).to eq(tracee)
    end

    it "kills process with KILL signal" do
      expect(Process).to receive(:kill).with("KILL", 4321)
      tracee.kill
    end

    it "wraps waitpid result in Event" do
      allow(Ptrace::Binding).to receive(:safe_waitpid).with(4321, flags: 7).and_return([4321, 0x2A00])

      event = tracee.wait(flags: 7)

      expect(event).to be_a(Ptrace::Event)
      expect(event.pid).to eq(4321)
      expect(event.raw_status).to eq(0x2A00)
    end

    it "raises unsupported arch error for unknown syscall layout" do
      expect { tracee.current_syscall(arch: :mips) }.to raise_error(Ptrace::UnsupportedArchError)
    end

    it "returns parsed /proc memory maps for pid" do
      maps = [Ptrace::ProcMaps::Mapping.new(
        start_addr: 0x1000,
        end_addr: 0x2000,
        permissions: "r--p",
        offset: 0,
        device: "00:00",
        inode: 0,
        pathname: nil
      )]
      expect(Ptrace::ProcMaps).to receive(:read).with(4321).and_return(maps)

      expect(tracee.memory_maps).to eq(maps)
    end

    it "reads ptrace event message via GETEVENTMSG" do
      expected = 123_456
      allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, pid, addr, data|
        expect(request).to eq(Ptrace::Constants::PTRACE_GETEVENTMSG)
        expect(pid).to eq(4321)
        expect(addr).to eq(0)
        pointer = Fiddle::Pointer.new(data)
        pointer[0, Fiddle::SIZEOF_VOIDP] = [expected].pack("J")
        0
      end

      expect(tracee.event_message).to eq(expected)
    end

    it "extracts seccomp filter data from event message" do
      allow(tracee).to receive(:event_message).and_return(0x1_0000_00AB)

      expect(tracee.seccomp_data).to eq(0xAB)
    end
  end

  describe "class controls" do
    it "waits any traced task and wraps result in Event" do
      allow(Ptrace::Binding).to receive(:safe_waitpid).with(-1, flags: 7).and_return([5555, 0x2A00])

      event = described_class.wait_any(flags: 7)

      expect(event).to be_a(Ptrace::Event)
      expect(event.pid).to eq(5555)
      expect(event.raw_status).to eq(0x2A00)
    end

    it "spawns tracee and sets default options" do
      event = instance_double(Ptrace::Event, stopped?: true)
      tracee = instance_double(described_class)

      allow(Process).to receive(:fork).and_return(1010)
      allow(described_class).to receive(:new).with(1010).and_return(tracee)
      allow(tracee).to receive(:wait).with(flags: Ptrace::Constants::WALL).and_return(event)
      expect(Ptrace::Binding).to receive(:safe_ptrace).with(
        Ptrace::Constants::PTRACE_SETOPTIONS,
        1010,
        0,
        Ptrace::Constants::PTRACE_O_TRACESYSGOOD
      )

      expect(described_class.spawn("/bin/true")).to eq(tracee)
    end

    it "does not set options when option mask is zero" do
      event = instance_double(Ptrace::Event, stopped?: true)
      tracee = instance_double(described_class)

      allow(Process).to receive(:fork).and_return(1011)
      allow(described_class).to receive(:new).with(1011).and_return(tracee)
      allow(tracee).to receive(:wait).with(flags: Ptrace::Constants::WALL).and_return(event)
      expect(Ptrace::Binding).not_to receive(:safe_ptrace).with(
        Ptrace::Constants::PTRACE_SETOPTIONS,
        anything,
        anything,
        anything
      )

      expect(described_class.spawn("/bin/true", options: 0)).to eq(tracee)
    end

    it "raises when initial stop is not observed on spawn" do
      event = instance_double(Ptrace::Event, stopped?: false, raw_status: 0x1234)
      tracee = instance_double(described_class)

      allow(Process).to receive(:fork).and_return(1012)
      allow(described_class).to receive(:new).with(1012).and_return(tracee)
      allow(tracee).to receive(:wait).with(flags: Ptrace::Constants::WALL).and_return(event)

      expect do
        described_class.spawn("/bin/true")
      end.to raise_error(Ptrace::Error, /did not stop after spawn/)
    end

    it "raises when fork fails" do
      allow(Process).to receive(:fork).and_return(nil)

      expect { described_class.spawn("/bin/true") }.to raise_error(Ptrace::Error, /fork failed/)
    end

    it "attaches and sets options" do
      event = instance_double(Ptrace::Event, stopped?: true)
      tracee = instance_double(described_class)

      expect(Ptrace::Binding).to receive(:safe_ptrace).with(Ptrace::Constants::PTRACE_ATTACH, 2222, 0, 0)
      allow(described_class).to receive(:new).with(2222).and_return(tracee)
      allow(tracee).to receive(:wait).with(flags: Ptrace::Constants::WALL).and_return(event)
      expect(Ptrace::Binding).to receive(:safe_ptrace).with(
        Ptrace::Constants::PTRACE_SETOPTIONS,
        2222,
        0,
        Ptrace::Constants::PTRACE_O_TRACESYSGOOD
      )

      expect(described_class.attach(2222)).to eq(tracee)
    end

    it "raises when initial stop is not observed on attach" do
      event = instance_double(Ptrace::Event, stopped?: false, raw_status: 0x2222)
      tracee = instance_double(described_class)

      allow(Ptrace::Binding).to receive(:safe_ptrace).with(Ptrace::Constants::PTRACE_ATTACH, 3333, 0, 0)
      allow(described_class).to receive(:new).with(3333).and_return(tracee)
      allow(tracee).to receive(:wait).with(flags: Ptrace::Constants::WALL).and_return(event)

      expect do
        described_class.attach(3333)
      end.to raise_error(Ptrace::Error, /did not stop after attach/)
    end

    it "seizes tracee with options" do
      tracee = instance_double(described_class)

      expect(Ptrace::Binding).to receive(:safe_ptrace).with(Ptrace::Constants::PTRACE_SEIZE, 4444, 0, 7)
      allow(described_class).to receive(:new).with(4444).and_return(tracee)

      expect(described_class.seize(4444, options: 7)).to eq(tracee)
    end
  end
end

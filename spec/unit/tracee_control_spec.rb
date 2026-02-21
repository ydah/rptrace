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

    it "sends LISTEN request and returns self" do
      expect(Ptrace::Binding).to receive(:safe_ptrace).with(Ptrace::Constants::PTRACE_LISTEN, 4321, 0, 0)
      expect(tracee.listen).to eq(tracee)
    end

    it "sets ptrace options and returns self" do
      expect(Ptrace::Binding).to receive(:safe_ptrace).with(
        Ptrace::Constants::PTRACE_SETOPTIONS,
        4321,
        0,
        7
      )

      expect(tracee.set_options(7)).to eq(tracee)
    end

    it "enables seccomp event tracing options" do
      expect(tracee).to receive(:set_options).with(
        Ptrace::Constants::PTRACE_O_TRACESYSGOOD | Ptrace::Constants::PTRACE_O_TRACESECCOMP
      ).and_return(tracee)

      expect(tracee.enable_seccomp_events!).to eq(tracee)
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

    it "reads seccomp metadata via ptrace helper" do
      allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, pid, addr, data|
        expect(request).to eq(Ptrace::Constants::PTRACE_SECCOMP_GET_METADATA)
        expect(pid).to eq(4321)
        expect(addr).to eq(Ptrace::CStructs.seccomp_metadata_size)
        pointer = Fiddle::Pointer.new(data)
        decoded = Ptrace::CStructs.unpack_seccomp_metadata(pointer[0, Ptrace::CStructs.seccomp_metadata_size])
        expect(decoded[:filter_off]).to eq(2)
        pointer[0, Ptrace::CStructs.seccomp_metadata_size] = Ptrace::CStructs.pack_seccomp_metadata(
          filter_off: 2,
          flags: 0x80
        )
        0
      end

      expect(tracee.seccomp_metadata(index: 2)).to eq(filter_off: 2, flags: 0x80)
    end

    it "reads and decodes seccomp filter instructions" do
      raw_filter = [
        [0x20, 0, 0, 4].pack("S<CCL<"),
        [0x06, 0, 0, 0x7FFF0000].pack("S<CCL<")
      ].join
      call_count = 0

      allow(Ptrace::Binding).to receive(:safe_ptrace) do |request, pid, addr, data|
        expect(request).to eq(Ptrace::Constants::PTRACE_SECCOMP_GET_FILTER)
        expect(pid).to eq(4321)
        expect(addr).to eq(1)

        call_count += 1
        if data.zero?
          2
        else
          pointer = Fiddle::Pointer.new(data)
          pointer[0, raw_filter.bytesize] = raw_filter
          2
        end
      end

      decoded = tracee.seccomp_filter(index: 1)
      expect(call_count).to eq(2)
      expect(decoded).to eq([
        { code: 0x20, jt: 0, jf: 0, k: 4 },
        { code: 0x06, jt: 0, jf: 0, k: 0x7FFF0000 }
      ])
    end

    it "returns empty seccomp filter when tracee has no filter instructions" do
      allow(Ptrace::Binding).to receive(:safe_ptrace).with(
        Ptrace::Constants::PTRACE_SECCOMP_GET_FILTER,
        4321,
        0,
        0
      ).and_return(0)

      expect(tracee.seccomp_filter(index: 0)).to eq([])
    end

    it "returns true when seccomp metadata query succeeds" do
      allow(tracee).to receive(:seccomp_metadata).with(index: 0).and_return(filter_off: 0, flags: 0)

      expect(tracee.seccomp_supported?).to be(true)
    end

    it "returns false when seccomp metadata query is unsupported" do
      allow(tracee).to receive(:seccomp_metadata).with(index: 0).and_raise(Ptrace::InvalidArgError.new("unsupported"))

      expect(tracee.seccomp_supported?).to be(false)
    end

    it "returns true when seccomp filter instructions are available" do
      allow(Ptrace::Binding).to receive(:safe_ptrace).with(
        Ptrace::Constants::PTRACE_SECCOMP_GET_FILTER,
        4321,
        1,
        0
      ).and_return(3)

      expect(tracee.seccomp_filter_available?(index: 1)).to be(true)
    end

    it "returns false when seccomp filter instructions are unavailable" do
      allow(Ptrace::Binding).to receive(:safe_ptrace).with(
        Ptrace::Constants::PTRACE_SECCOMP_GET_FILTER,
        4321,
        1,
        0
      ).and_return(0)

      expect(tracee.seccomp_filter_available?(index: 1)).to be(false)
    end

    it "returns false when seccomp filter query is unsupported" do
      allow(Ptrace::Binding).to receive(:safe_ptrace).with(
        Ptrace::Constants::PTRACE_SECCOMP_GET_FILTER,
        4321,
        1,
        0
      ).and_raise(Ptrace::InvalidArgError.new("unsupported"))

      expect(tracee.seccomp_filter_available?(index: 1)).to be(false)
    end

    it "decodes known seccomp metadata flag names" do
      allow(tracee).to receive(:seccomp_metadata).with(index: 0).and_return(
        filter_off: 0,
        flags: Ptrace::Constants::SECCOMP_FILTER_FLAG_TSYNC | Ptrace::Constants::SECCOMP_FILTER_FLAG_LOG
      )

      expect(tracee.seccomp_metadata_flag_names).to eq(%i[tsync log])
    end

    it "reports unknown seccomp metadata flag bits" do
      allow(tracee).to receive(:seccomp_metadata).with(index: 0).and_return(filter_off: 0, flags: 0x40)

      expect(tracee.seccomp_metadata_flag_names).to eq([:unknown_0x40])
    end

    it "rejects negative seccomp metadata index" do
      expect do
        tracee.seccomp_metadata(index: -1)
      end.to raise_error(ArgumentError, /index must be non-negative/)
    end

    it "rejects negative seccomp filter index" do
      expect do
        tracee.seccomp_filter(index: -1)
      end.to raise_error(ArgumentError, /index must be non-negative/)
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

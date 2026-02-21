# frozen_string_literal: true

RSpec.describe Rptrace::SeccompEvent do
  let(:tracee) { instance_double(Rptrace::Tracee, pid: 4321) }
  let(:syscall) { Rptrace::Syscall::SyscallInfo.new(number: 257, name: :openat, arg_names: [], arg_types: []) }

  it "stores seccomp event fields" do
    event = described_class.new(tracee: tracee, syscall: syscall, data: 0xABCD, metadata_flags: %i[tsync log])

    expect(event.tracee).to eq(tracee)
    expect(event.syscall).to eq(syscall)
    expect(event.data).to eq(0xABCD)
    expect(event.metadata_flags).to eq(%i[tsync log])
  end

  it "formats event as readable string" do
    event = described_class.new(tracee: tracee, syscall: syscall, data: 0x1, metadata_flags: [:log])

    expect(event.to_s).to eq("seccomp(pid=4321, syscall=openat, data=0x1 flags=log)")
  end

  it "omits flags section when metadata flags are empty" do
    event = described_class.new(tracee: tracee, syscall: syscall, data: 0x2, metadata_flags: [])

    expect(event.to_s).to eq("seccomp(pid=4321, syscall=openat, data=0x2)")
  end
end

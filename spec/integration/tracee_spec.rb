# frozen_string_literal: true

RSpec.describe Ptrace::Tracee do
  it "spawns and traces /bin/true" do
    skip "linux-only integration spec" unless Ptrace.linux?

    tracee = described_class.spawn("/bin/true")
    tracee.cont
    event = tracee.wait(flags: Ptrace::Constants::__WALL)

    expect(event.exited?).to be(true)
    expect(event.exit_status).to eq(0)
  ensure
    tracee&.detach
  end
end

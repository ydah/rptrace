# frozen_string_literal: true

RSpec.describe Ptrace::WaitStatus do
  it "detects normal exit" do
    status = 42 << 8

    expect(described_class.exited?(status)).to be(true)
    expect(described_class.exit_status(status)).to eq(42)
  end

  it "detects stop signal" do
    status = 0x057F

    expect(described_class.stopped?(status)).to be(true)
    expect(described_class.stop_signal(status)).to eq(5)
  end

  it "detects signal termination" do
    status = 9

    expect(described_class.signaled?(status)).to be(true)
    expect(described_class.term_signal(status)).to eq(9)
  end
end

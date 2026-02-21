# frozen_string_literal: true

RSpec.describe Rptrace::Binding do
  it "defines key PTRACE constants" do
    expect(described_class::PTRACE_TRACEME).to eq(0)
    expect(described_class::PTRACE_SYSCALL).to eq(24)
    expect(described_class::PTRACE_SEIZE).to eq(0x4206)
  end

  it "loads ptrace symbol" do
    expect(described_class).to respond_to(:ptrace)
  end
end

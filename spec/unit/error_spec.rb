# frozen_string_literal: true

RSpec.describe Rptrace::Error do
  it "formats ptrace context when errno and request are present" do
    error = described_class.new("Permission denied", errno: 1, request: :attach)

    expect(error.errno).to eq(1)
    expect(error.request).to eq(:attach)
    expect(error.message).to include("ptrace(attach): Permission denied (errno=1)")
  end

  it "keeps plain message when context is missing" do
    error = described_class.new("plain")

    expect(error.message).to eq("plain")
    expect(error.errno).to be_nil
    expect(error.request).to be_nil
  end
end

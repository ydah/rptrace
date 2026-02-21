# frozen_string_literal: true

RSpec.describe Ptrace do
  it "has a version number" do
    expect(Ptrace::VERSION).not_to be_nil
  end

  it "uses top-level Ptrace namespace" do
    expect(defined?(Ptrace::Ruby)).to be_nil
  end

  it "exposes linux? helper as boolean" do
    expect([true, false]).to include(Ptrace.linux?)
  end

  it "exposes ptrace privilege helper as boolean" do
    expect([true, false]).to include(Ptrace.ptrace_privileged?)
  end

  it "exposes ptrace permission diagnostics as hash" do
    expect(Ptrace.ptrace_permissions).to be_a(Hash)
    expect(Ptrace.ptrace_permissions).to include(:hints)
  end
end

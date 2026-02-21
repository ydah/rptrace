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

  it "exposes ptrace privilege assertion helper" do
    allow(Ptrace::Permission).to receive(:ensure_privileged!).with(request: :attach).and_return({ptrace_privileged: true})

    expect(Ptrace.ensure_ptrace_privileged!(request: :attach)).to eq({ptrace_privileged: true})
  end
end

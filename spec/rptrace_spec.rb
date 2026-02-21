# frozen_string_literal: true

RSpec.describe Rptrace do
  it "has a version number" do
    expect(Rptrace::VERSION).not_to be_nil
  end

  it "uses top-level Rptrace namespace" do
    expect(defined?(Rptrace::Ruby)).to be_nil
  end

  it "exposes linux? helper as boolean" do
    expect([true, false]).to include(Rptrace.linux?)
  end

  it "exposes ptrace privilege helper as boolean" do
    expect([true, false]).to include(Rptrace.ptrace_privileged?)
  end

  it "exposes ptrace permission diagnostics as hash" do
    expect(Rptrace.ptrace_permissions).to be_a(Hash)
    expect(Rptrace.ptrace_permissions).to include(:hints)
  end

  it "exposes ptrace privilege assertion helper" do
    allow(Rptrace::Permission).to receive(:ensure_privileged!).with(request: :attach).and_return({ptrace_privileged: true})

    expect(Rptrace.ensure_ptrace_privileged!(request: :attach)).to eq({ptrace_privileged: true})
  end
end

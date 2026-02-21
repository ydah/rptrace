# frozen_string_literal: true

require "open3"
require "rbconfig"

RSpec.describe "examples" do
  def integration_env
    "PTRACE_RUN_INTEGRATION"
  end

  def root_dir
    File.expand_path("../..", __dir__)
  end

  def ensure_integration_environment!
    skip "linux-only integration spec" unless Ptrace.linux?
    return if ENV[integration_env] == "1"

    skip "set #{integration_env}=1 to run ptrace integration specs"
  end

  def with_ptrace_permission
    yield
  rescue Ptrace::PermissionError => e
    skip "ptrace permission required: #{e.message}"
  end

  def run_example(*args)
    Open3.capture3("bundle", "exec", RbConfig.ruby, *args, chdir: root_dir)
  end

  before do
    ensure_integration_environment!
  end

  it "runs simple_strace example" do
    with_ptrace_permission do
      stdout, stderr, status = run_example("examples/simple_strace.rb", "/bin/true")

      expect(status.success?).to be(true), stderr
      expect(stdout).to include(" = ")
    end
  end

  it "runs syscall_counter example" do
    with_ptrace_permission do
      stdout, stderr, status = run_example("examples/syscall_counter.rb", "/bin/true")

      expect(status.success?).to be(true), stderr
      expect(stdout).to match(/\S+\s+\d+/)
    end
  end

  it "runs file_access_tracer example" do
    with_ptrace_permission do
      stdout, stderr, status = run_example("examples/file_access_tracer.rb", "/bin/ls", "/tmp")

      expect(status.success?).to be(true), stderr
      expect(stdout).to include("open").or include("openat")
    end
  end

  it "runs memory_reader example" do
    with_ptrace_permission do
      child_pid = Process.spawn("/bin/sleep", "2")
      stdout, stderr, status = run_example("examples/memory_reader.rb", child_pid.to_s, "16")

      expect(status.success?).to be(true), stderr
      expect(stdout).to include("pid=#{child_pid}")
      expect(stdout).to include("size=16")
    ensure
      begin
        Process.kill("KILL", child_pid)
      rescue Errno::ESRCH
        nil
      end

      begin
        Process.wait(child_pid)
      rescue Errno::ECHILD
        nil
      end
    end
  end
end

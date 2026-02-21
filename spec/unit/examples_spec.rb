# frozen_string_literal: true

require "open3"
require "rbconfig"

RSpec.describe "examples" do
  def root_dir
    File.expand_path("../..", __dir__)
  end

  def example_files
    %w[
      examples/simple_strace.rb
      examples/syscall_counter.rb
      examples/file_access_tracer.rb
      examples/memory_reader.rb
    ]
  end

  it "has syntactically valid example scripts" do
    example_files.each do |path|
      stdout, stderr, status = Open3.capture3(
        "bundle", "exec", RbConfig.ruby, "-c", path,
        chdir: root_dir
      )

      expect(status.success?).to be(true), "#{path} syntax check failed:\n#{stdout}\n#{stderr}"
    end
  end

  it "prints usage for simple_strace without args" do
    _stdout, stderr, status = Open3.capture3("bundle", "exec", RbConfig.ruby, "examples/simple_strace.rb", chdir: root_dir)

    expect(status.exitstatus).to eq(1)
    expect(stderr).to include("usage: bundle exec ruby examples/simple_strace.rb")
  end

  it "prints usage for syscall_counter without args" do
    _stdout, stderr, status = Open3.capture3("bundle", "exec", RbConfig.ruby, "examples/syscall_counter.rb", chdir: root_dir)

    expect(status.exitstatus).to eq(1)
    expect(stderr).to include("usage: bundle exec ruby examples/syscall_counter.rb")
  end

  it "prints usage for file_access_tracer without args" do
    _stdout, stderr, status = Open3.capture3("bundle", "exec", RbConfig.ruby, "examples/file_access_tracer.rb", chdir: root_dir)

    expect(status.exitstatus).to eq(1)
    expect(stderr).to include("usage: bundle exec ruby examples/file_access_tracer.rb")
  end

  it "prints usage for memory_reader without args" do
    _stdout, stderr, status = Open3.capture3("bundle", "exec", RbConfig.ruby, "examples/memory_reader.rb", chdir: root_dir)

    expect(status.exitstatus).to eq(1)
    expect(stderr).to include("usage: bundle exec ruby examples/memory_reader.rb")
  end
end

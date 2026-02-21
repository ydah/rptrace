# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require "ptrace/syscall_table/generator"

RSpec.describe Ptrace::SyscallTable::Generator do
  describe ".parse_header" do
    it "extracts syscall numbers from numeric __NR defines" do
      header = <<~HEADER
        #define __NR_read 0
        #define __NR_write 1
        #define __NR_openat (__NR_Linux + 56)
        #define __NR3264_lseek 62
      HEADER

      expect(described_class.parse_header(header)).to eq(
        [
          [0, :read],
          [1, :write],
          [62, :lseek]
        ]
      )
    end
  end

  describe ".render_table" do
    it "renders a syscall table module with BY_NAME index" do
      rendered = described_class.render_table(module_name: "X86_64", entries: [[0, :read], [1, :write]])

      expect(rendered).to include("module X86_64")
      expect(rendered).to include("name: :read")
      expect(rendered).to include("name: :write")
      expect(rendered).to include("BY_NAME = TABLE.each_with_object({})")
    end
  end

  describe ".generate_for" do
    it "writes a generated table using env-provided header path" do
      Dir.mktmpdir do |tmpdir|
        root_dir = File.join(tmpdir, "project")
        header_path = File.join(tmpdir, "unistd_64.h")
        output_dir = File.join(root_dir, "lib/ptrace/syscall_table")
        output_path = File.join(output_dir, "x86_64.rb")

        FileUtils.mkdir_p(output_dir)
        File.write(header_path, "#define __NR_read 0\n#define __NR_write 1\n")

        original_env = ENV["PTRACE_SYSCALL_HEADER_X86_64"]
        ENV["PTRACE_SYSCALL_HEADER_X86_64"] = header_path
        result = described_class.generate_for(:x86_64, root_dir: root_dir)

        expect(result[:entries_count]).to eq(2)
        expect(result[:output_path]).to eq(output_path)
        expect(File.read(output_path)).to include("name: :read")
        expect(File.read(output_path)).to include("name: :write")
      ensure
        ENV["PTRACE_SYSCALL_HEADER_X86_64"] = original_env
      end
    end

    it "raises for unsupported architecture names" do
      expect do
        described_class.generate_for(:mips, root_dir: Dir.pwd)
      end.to raise_error(ArgumentError, /unsupported arch/)
    end

    it "raises when env header path is invalid" do
      original_env = ENV["PTRACE_SYSCALL_HEADER_X86_64"]
      ENV["PTRACE_SYSCALL_HEADER_X86_64"] = "/tmp/does-not-exist-header.h"

      expect do
        described_class.generate_for(:x86_64, root_dir: Dir.pwd)
      end.to raise_error(ArgumentError, /does not exist/)
    ensure
      ENV["PTRACE_SYSCALL_HEADER_X86_64"] = original_env
    end

    it "raises when header has no parseable syscall entries" do
      Dir.mktmpdir do |tmpdir|
        root_dir = File.join(tmpdir, "project")
        header_path = File.join(tmpdir, "empty.h")
        FileUtils.mkdir_p(File.join(root_dir, "lib/ptrace/syscall_table"))
        File.write(header_path, "#define SOMETHING_ELSE 1\n")

        original_env = ENV["PTRACE_SYSCALL_HEADER_X86_64"]
        ENV["PTRACE_SYSCALL_HEADER_X86_64"] = header_path

        expect do
          described_class.generate_for(:x86_64, root_dir: root_dir)
        end.to raise_error(ArgumentError, /no syscall entries found/)
      ensure
        ENV["PTRACE_SYSCALL_HEADER_X86_64"] = original_env
      end
    end
  end
end

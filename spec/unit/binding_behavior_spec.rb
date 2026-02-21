# frozen_string_literal: true

require "fiddle"

RSpec.describe Rptrace::Binding do
  describe ".safe_ptrace" do
    it "returns -1 without raising when errno is 0 (PEEKDATA success case)" do
      allow(described_class).to receive(:ptrace) do
        Fiddle.last_error = 0
        -1
      end

      expect(described_class.safe_ptrace(:peek, 1, 2, 3)).to eq(-1)
    end

    it "maps EPERM to PermissionError" do
      allow(described_class).to receive(:ptrace) do
        Fiddle.last_error = Errno::EPERM::Errno
        -1
      end

      expect do
        described_class.safe_ptrace(:attach, 1, 0, 0)
      end.to raise_error(Rptrace::PermissionError, /CAP_SYS_PTRACE/)
    end

    it "includes Yama guidance in PermissionError messages" do
      allow(described_class).to receive(:ptrace) do
        Fiddle.last_error = Errno::EPERM::Errno
        -1
      end

      expect do
        described_class.safe_ptrace(:attach, 1, 0, 0)
      end.to raise_error(Rptrace::PermissionError, /ptrace_scope/)
    end

    it "maps unknown errno to generic Error" do
      allow(described_class).to receive(:ptrace) do
        Fiddle.last_error = 1234
        -1
      end

      expect do
        described_class.safe_ptrace(:attach, 1, 0, 0)
      end.to raise_error(Rptrace::Error)
    end
  end

  describe ".safe_waitpid" do
    it "returns pid and decoded status on success" do
      allow(described_class).to receive(:waitpid) do |pid, status_ptr, _flags|
        status_ptr[0, Fiddle::SIZEOF_INT] = [42 << 8].pack("i")
        pid
      end

      waited_pid, status = described_class.safe_waitpid(123, flags: 0)

      expect(waited_pid).to eq(123)
      expect(status).to eq(42 << 8)
    end

    it "retries when waitpid is interrupted by signal" do
      attempts = 0

      allow(described_class).to receive(:waitpid) do |pid, status_ptr, _flags|
        attempts += 1

        if attempts == 1
          Fiddle.last_error = Errno::EINTR::Errno
          -1
        else
          status_ptr[0, Fiddle::SIZEOF_INT] = [7 << 8].pack("i")
          pid
        end
      end

      waited_pid, status = described_class.safe_waitpid(123, flags: 0)

      expect(attempts).to eq(2)
      expect(waited_pid).to eq(123)
      expect(status).to eq(7 << 8)
    end

    it "raises mapped error when waitpid fails" do
      allow(described_class).to receive(:waitpid) do |_pid, _status_ptr, _flags|
        Fiddle.last_error = Errno::ESRCH::Errno
        -1
      end

      expect { described_class.safe_waitpid(123, flags: 0) }.to raise_error(Rptrace::NoProcessError)
    end
  end
end

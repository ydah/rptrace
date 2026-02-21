# frozen_string_literal: true

RSpec.describe Ptrace do
  describe ".trace" do
    it "passes ptrace options through to Tracee.spawn" do
      tracee = instance_double(Ptrace::Tracee)
      allow(tracee).to receive(:detach)
      expect(Ptrace::Tracee).to receive(:spawn).with("/bin/true", options: 0).and_return(tracee)

      described_class.trace("/bin/true", options: 0) { :ok }
    end

    it "detaches tracee after block execution" do
      tracee = instance_double(Ptrace::Tracee)
      allow(tracee).to receive(:detach)
      allow(Ptrace::Tracee).to receive(:spawn).and_return(tracee)

      yielded = nil
      described_class.trace("/bin/true") { |t| yielded = t }

      expect(yielded).to eq(tracee)
      expect(tracee).to have_received(:detach)
    end

    it "detaches tracee even when block raises" do
      tracee = instance_double(Ptrace::Tracee)
      allow(tracee).to receive(:detach)
      allow(Ptrace::Tracee).to receive(:spawn).and_return(tracee)

      expect do
        described_class.trace("/bin/true") { raise "boom" }
      end.to raise_error(RuntimeError, "boom")
      expect(tracee).to have_received(:detach)
    end

    it "suppresses detach errors during ensure" do
      tracee = instance_double(Ptrace::Tracee)
      allow(tracee).to receive(:detach).and_raise(Ptrace::NoProcessError.new("gone"))
      allow(Ptrace::Tracee).to receive(:spawn).and_return(tracee)

      expect { described_class.trace("/bin/true") { :ok } }.not_to raise_error
    end
  end

  describe ".strace" do
    it "yields enter and exit syscall events" do
      tracee = instance_double(Ptrace::Tracee)
      allow(Ptrace::Tracee).to receive(:spawn).and_return(tracee)
      allow(tracee).to receive(:detach)
      allow(tracee).to receive(:syscall).and_return(tracee)

      enter_stop = instance_double(Ptrace::Event, exited?: false, signaled?: false, syscall_stop?: true)
      exit_stop = instance_double(Ptrace::Event, exited?: false, signaled?: false, syscall_stop?: false)
      process_exit = instance_double(Ptrace::Event, exited?: true, signaled?: false, syscall_stop?: false)
      allow(tracee).to receive(:wait).and_return(enter_stop, exit_stop, process_exit)

      syscall_info = Ptrace::Syscall::SyscallInfo.new(
        number: 1,
        name: :write,
        arg_names: %i[fd buf count],
        arg_types: %i[fd buf size]
      )
      allow(tracee).to receive(:current_syscall).and_return(syscall_info)
      allow(tracee).to receive(:syscall_args).and_return([1, 0x1000, 12])
      allow(tracee).to receive(:syscall_return).and_return(12)

      yielded = []
      described_class.strace("/bin/echo", "hello") { |event| yielded << event }

      expect(yielded.size).to eq(2)
      expect(yielded.first).to be_enter
      expect(yielded.last).to be_exit
      expect(yielded.last.return_value).to eq(12)
      expect(tracee).to have_received(:detach)
    end

    it "skips non-syscall stops and exits without yielding" do
      tracee = instance_double(Ptrace::Tracee)
      allow(Ptrace::Tracee).to receive(:spawn).and_return(tracee)
      allow(tracee).to receive(:detach)
      allow(tracee).to receive(:syscall).and_return(tracee)

      not_syscall_stop = instance_double(Ptrace::Event, exited?: false, signaled?: false, syscall_stop?: false)
      process_exit = instance_double(Ptrace::Event, exited?: true, signaled?: false, syscall_stop?: false)
      allow(tracee).to receive(:wait).and_return(not_syscall_stop, process_exit)

      yielded = []
      described_class.strace("/bin/echo", "hello") { |event| yielded << event }

      expect(yielded).to eq([])
    end

    it "follows clone descendants when follow_children is enabled" do
      root_tracee = instance_double(Ptrace::Tracee)
      child_tracee = instance_double(Ptrace::Tracee)
      allow(root_tracee).to receive(:pid).and_return(111)
      allow(root_tracee).to receive(:detach)
      allow(root_tracee).to receive(:syscall).and_return(root_tracee)
      allow(root_tracee).to receive(:event_message).and_return(222)
      allow(child_tracee).to receive(:pid).and_return(222)
      allow(child_tracee).to receive(:syscall).and_return(child_tracee)
      follow_children_options =
        Ptrace::Tracee::DEFAULT_TRACE_OPTIONS |
        Ptrace::Constants::PTRACE_O_TRACECLONE |
        Ptrace::Constants::PTRACE_O_TRACEFORK |
        Ptrace::Constants::PTRACE_O_TRACEVFORK
      allow(child_tracee).to receive(:set_options).with(follow_children_options).and_return(child_tracee)

      expect(Ptrace::Tracee).to receive(:spawn).with(
        "/bin/echo",
        "hello",
        options: follow_children_options
      ).and_return(root_tracee)
      expect(Ptrace::Tracee).to receive(:new).with(222).and_return(child_tracee)

      clone_event = instance_double(
        Ptrace::Event,
        pid: 111,
        exited?: false,
        signaled?: false,
        syscall_stop?: false,
        fork_like_event?: true
      )
      root_exit = instance_double(
        Ptrace::Event,
        pid: 111,
        exited?: true,
        signaled?: false,
        syscall_stop?: false,
        fork_like_event?: false
      )
      child_enter = instance_double(
        Ptrace::Event,
        pid: 222,
        exited?: false,
        signaled?: false,
        syscall_stop?: true,
        fork_like_event?: false
      )
      child_exit = instance_double(
        Ptrace::Event,
        pid: 222,
        exited?: false,
        signaled?: false,
        syscall_stop?: true,
        fork_like_event?: false
      )
      child_dead = instance_double(
        Ptrace::Event,
        pid: 222,
        exited?: true,
        signaled?: false,
        syscall_stop?: false,
        fork_like_event?: false
      )
      allow(Ptrace::Tracee).to receive(:wait_any).and_return(clone_event, root_exit, child_enter, child_exit, child_dead)

      syscall_info = Ptrace::Syscall::SyscallInfo.new(
        number: 1,
        name: :write,
        arg_names: %i[fd buf count],
        arg_types: %i[fd buf size]
      )
      allow(child_tracee).to receive(:current_syscall).and_return(syscall_info)
      allow(child_tracee).to receive(:syscall_args).and_return([1, 0x1000, 3])
      allow(child_tracee).to receive(:syscall_return).and_return(3)

      yielded = []
      described_class.strace("/bin/echo", "hello", follow_children: true) { |event| yielded << event }

      expect(yielded.size).to eq(2)
      expect(yielded.first).to be_enter
      expect(yielded.last).to be_exit
      expect(yielded.map { |event| event.tracee.pid }).to eq([222, 222])
      expect(root_tracee).to have_received(:detach)
    end
  end
end

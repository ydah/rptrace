# ptrace-ruby

`ptrace-ruby` is a Ruby wrapper for Linux `ptrace(2)` focused on building tracers and debugger-like tooling with a Ruby-friendly API.

## Overview and Motivation

Linux `ptrace(2)` is powerful but low-level. This gem wraps process control, register/memory access, and syscall decoding behind a small Ruby API so you can build:

- `strace`-like tools
- process instrumentation utilities
- debugger-oriented experiments

## Features

- Top-level namespace is `Ptrace` (no `Ptrace::Ruby` nesting)
- `Tracee` API for `spawn`, `attach`, `cont`, `syscall`, `detach`, and `wait`
- Register and memory wrappers (`Registers`, `Memory`)
- `/proc/<pid>/maps` parser (`ProcMaps`, `Tracee#memory_maps`)
- Syscall lookup (`Ptrace::Syscall`) for `x86_64`/`aarch64`
- High-level tracing helper `Ptrace.strace`

## Installation

Add this line to your application's Gemfile:

```ruby
gem "ptrace-ruby"
```

And then execute:

```bash
bundle install
```

## Quick Start

```ruby
require "ptrace"

Ptrace.strace("/bin/ls", "-la", "/tmp") do |event|
  next unless event.exit?

  puts event
end
```

## Permission Guide

`ptrace` requires privilege on Linux:

- run as `root`, or
- run with `CAP_SYS_PTRACE`, and
- ensure Yama policy allows tracing (`/proc/sys/kernel/yama/ptrace_scope`)

Integration specs are opt-in and require:

```bash
PTRACE_RUN_INTEGRATION=1 bundle exec rspec spec/integration
```

## Examples

- `examples/simple_strace.rb`
- `examples/syscall_counter.rb`
- `examples/file_access_tracer.rb`
- `examples/memory_reader.rb`

## API Reference

- Generate docs: `bundle exec yard doc`
- Open index: `doc/index.html`

## Development

```bash
bundle exec rspec
```

Run specs with coverage threshold check:

```bash
COVERAGE=1 COVERAGE_MIN_LINE=95 bundle exec rspec spec/unit spec/ptrace_spec.rb
```

Generate syscall tables from Linux headers (`x86_64` / `aarch64`):

```bash
bundle exec rake syscall:generate
```

You can override header paths with:

- `PTRACE_SYSCALL_HEADER_X86_64`
- `PTRACE_SYSCALL_HEADER_AARCH64`

Optional task controls:

- `ARCH=x86_64` (or `ARCH=x86_64,aarch64`) to limit architectures
- `STRICT=1` to fail if any requested architecture header is missing

Generate YARD documentation:

```bash
bundle exec yard doc
```

## Limitations

- Linux only
- Ruby 3.1+
- Architecture support: `x86_64` and `aarch64`
- Integration tests require ptrace permission (`root` or `CAP_SYS_PTRACE`)

## License

MIT

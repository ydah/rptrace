# ptrace-ruby

`ptrace-ruby` is an in-progress Ruby gem that wraps Linux `ptrace(2)` with a Ruby-friendly API.

## Status

Initial scaffolding is in place:

- top-level namespace: `Ptrace` (no `Ptrace::Ruby` nesting)
- low-level constants and FFI binding entry points
- basic process/event model skeleton (`Tracee`, `Event`, `SyscallEvent`)
- initial syscall metadata tables for `x86_64` and `aarch64`

## Installation

Add this line to your application's Gemfile:

```ruby
gem "ptrace-ruby"
```

And then execute:

```bash
bundle install
```

## Usage (WIP)

```ruby
require "ptrace"

Ptrace.strace("/bin/echo", "hello") do |event|
  next unless event.exit?
  puts event
end
```

## Platform

- Linux only (intended target)
- Ruby 3.1+

## Development

```bash
bundle exec rspec
```

## License

MIT

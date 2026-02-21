# frozen_string_literal: true

if ENV["COVERAGE"] == "1"
  require "simplecov"

  minimum_line = Integer(ENV.fetch("COVERAGE_MIN_LINE", "95"), 10)

  SimpleCov.start do
    track_files "lib/**/*.rb"
    add_filter "/spec/"
    add_filter "/sig/"
    minimum_coverage line: minimum_line
  end
end

require "ptrace"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

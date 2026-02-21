# frozen_string_literal: true

module Rptrace
  module SyscallTable
    # Generates syscall table Ruby files from Linux unistd headers.
    module Generator
      # Raised when syscall header cannot be resolved for an architecture.
      class HeaderNotFoundError < ArgumentError; end

      module_function

      # Header lookup and output mapping by architecture.
      ARCH_CONFIG = {
        x86_64: {
          module_name: "X86_64",
          output_path: "lib/rptrace/syscall_table/x86_64.rb",
          env_key: "PTRACE_SYSCALL_HEADER_X86_64",
          header_candidates: [
            "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
            "/usr/include/asm/unistd_64.h",
            "/usr/include/x86_64-linux-gnu/asm/unistd.h"
          ].freeze
        }.freeze,
        aarch64: {
          module_name: "AARCH64",
          output_path: "lib/rptrace/syscall_table/aarch64.rb",
          env_key: "PTRACE_SYSCALL_HEADER_AARCH64",
          header_candidates: [
            "/usr/include/aarch64-linux-gnu/asm/unistd.h",
            "/usr/aarch64-linux-gnu/include/asm/unistd.h",
            "/usr/include/asm-generic/unistd.h"
          ].freeze
        }.freeze
      }.freeze

      # Matches numeric __NR_* macro definitions.
      DEFINE_REGEX = /^\s*#\s*define\s+__NR(?:3264)?_([a-zA-Z0-9_]+)\s+([0-9]+)\b/.freeze

      # Generates tables for all configured architectures.
      #
      # @param root_dir [String]
      # @param arches [Array<Symbol>]
      # @param skip_missing [Boolean] skip architectures without headers
      # @return [Array<Hash>]
      def generate_all(root_dir: Dir.pwd, arches: ARCH_CONFIG.keys, skip_missing: false)
        generated = []

        arches.each do |arch|
          begin
            generated << generate_for(arch, root_dir: root_dir)
          rescue HeaderNotFoundError
            raise unless skip_missing
          end
        end

        generated
      end

      # Generates tables and reports skipped architectures.
      #
      # @param root_dir [String]
      # @param arches [Array<Symbol>]
      # @return [Hash]
      def generate_available(root_dir: Dir.pwd, arches: ARCH_CONFIG.keys)
        generated = []
        skipped = []

        arches.each do |arch|
          begin
            generated << generate_for(arch, root_dir: root_dir)
          rescue HeaderNotFoundError => e
            skipped << { arch: arch.to_sym, reason: e.message }
          end
        end

        { generated: generated, skipped: skipped }
      end

      # Generates one syscall table file.
      #
      # @param arch [Symbol]
      # @param root_dir [String]
      # @return [Hash]
      def generate_for(arch, root_dir: Dir.pwd)
        config = ARCH_CONFIG.fetch(arch.to_sym) do
          raise ArgumentError, "unsupported arch: #{arch}"
        end
        header_path = resolve_header_path(config)
        entries = parse_header(File.read(header_path))
        raise ArgumentError, "no syscall entries found in #{header_path}" if entries.empty?

        output_path = File.expand_path(config.fetch(:output_path), root_dir)
        File.write(output_path, render_table(module_name: config.fetch(:module_name), entries: entries))

        {
          arch: arch.to_sym,
          header_path: header_path,
          output_path: output_path,
          entries_count: entries.size
        }
      end

      # Parses #define __NR_* entries from header content.
      #
      # @param content [String]
      # @return [Array<(Integer, Symbol)>]
      def parse_header(content)
        by_number = {}

        content.each_line do |line|
          match = line.match(DEFINE_REGEX)
          next unless match

          name = match[1].to_sym
          number = Integer(match[2], 10)
          by_number[number] ||= name
        end

        by_number.sort_by { |number, _name| number }
      end

      # Renders a syscall table Ruby source.
      #
      # @param module_name [String]
      # @param entries [Array<(Integer, Symbol)>]
      # @return [String]
      def render_table(module_name:, entries:)
        table_lines = entries.map do |number, name|
          "        #{number} => Syscall::SyscallInfo.new(number: #{number}, name: :#{name}, arg_names: [], arg_types: [])"
        end

        <<~RUBY
          # frozen_string_literal: true

          module Rptrace
            module SyscallTable
              module #{module_name}
                TABLE = {
          #{table_lines.join(",\n")}
                }.freeze

                BY_NAME = TABLE.each_with_object({}) do |(_number, info), map|
                  map[info.name] = info
                end.freeze
              end
            end
          end
        RUBY
      end

      def resolve_header_path(config)
        env_key = config.fetch(:env_key)
        env_value = ENV[env_key]

        if env_value && !env_value.empty?
          expanded = File.expand_path(env_value)
          return expanded if File.file?(expanded)

          raise HeaderNotFoundError, "header path from #{env_key} does not exist: #{expanded}"
        end

        config.fetch(:header_candidates).each do |candidate|
          expanded = File.expand_path(candidate)
          return expanded if File.file?(expanded)
        end

        raise HeaderNotFoundError, "no syscall header found. set #{env_key}=<path-to-header>"
      end
      private_class_method :resolve_header_path
    end
  end
end

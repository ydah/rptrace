# frozen_string_literal: true

module Ptrace
  module SyscallTable
    module Generator
      module_function

      ARCH_CONFIG = {
        x86_64: {
          module_name: "X86_64",
          output_path: "lib/ptrace/syscall_table/x86_64.rb",
          env_key: "PTRACE_SYSCALL_HEADER_X86_64",
          header_candidates: [
            "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
            "/usr/include/asm/unistd_64.h",
            "/usr/include/x86_64-linux-gnu/asm/unistd.h"
          ].freeze
        }.freeze,
        aarch64: {
          module_name: "AARCH64",
          output_path: "lib/ptrace/syscall_table/aarch64.rb",
          env_key: "PTRACE_SYSCALL_HEADER_AARCH64",
          header_candidates: [
            "/usr/include/aarch64-linux-gnu/asm/unistd.h",
            "/usr/aarch64-linux-gnu/include/asm/unistd.h",
            "/usr/include/asm-generic/unistd.h"
          ].freeze
        }.freeze
      }.freeze

      DEFINE_REGEX = /^\s*#\s*define\s+__NR(?:3264)?_([a-zA-Z0-9_]+)\s+([0-9]+)\b/.freeze

      def generate_all(root_dir: Dir.pwd, arches: ARCH_CONFIG.keys)
        arches.map { |arch| generate_for(arch, root_dir: root_dir) }
      end

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

      def render_table(module_name:, entries:)
        table_lines = entries.map do |number, name|
          "        #{number} => Syscall::SyscallInfo.new(number: #{number}, name: :#{name}, arg_names: [], arg_types: [])"
        end

        <<~RUBY
          # frozen_string_literal: true

          module Ptrace
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

          raise ArgumentError, "header path from #{env_key} does not exist: #{expanded}"
        end

        config.fetch(:header_candidates).each do |candidate|
          expanded = File.expand_path(candidate)
          return expanded if File.file?(expanded)
        end

        raise ArgumentError, "no syscall header found. set #{env_key}=<path-to-header>"
      end
      private_class_method :resolve_header_path
    end
  end
end

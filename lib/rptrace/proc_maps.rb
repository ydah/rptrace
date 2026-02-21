# frozen_string_literal: true

module Rptrace
  # Parser for Linux /proc/<pid>/maps entries.
  module ProcMaps
    # Parsed memory mapping row from /proc/<pid>/maps.
    #
    # @!attribute [r] start_addr
    #   @return [Integer] mapping start address (inclusive)
    # @!attribute [r] end_addr
    #   @return [Integer] mapping end address (exclusive)
    # @!attribute [r] permissions
    #   @return [String] raw permissions string, e.g. "r-xp"
    # @!attribute [r] offset
    #   @return [Integer] file offset
    # @!attribute [r] device
    #   @return [String] device major:minor
    # @!attribute [r] inode
    #   @return [Integer] inode number
    # @!attribute [r] pathname
    #   @return [String, nil] file path or pseudo label
    Mapping = Struct.new(:start_addr, :end_addr, :permissions, :offset, :device, :inode, :pathname, keyword_init: true) do
      # @return [Integer] region byte size
      def size
        end_addr - start_addr
      end

      # @return [Boolean]
      def readable?
        permissions[0] == "r"
      end

      # @return [Boolean]
      def writable?
        permissions[1] == "w"
      end

      # @return [Boolean]
      def executable?
        permissions[2] == "x"
      end

      # @return [Boolean]
      def private?
        permissions[3] == "p"
      end

      # @return [Boolean]
      def shared?
        permissions[3] == "s"
      end

      # @return [Boolean]
      def anonymous?
        pathname.nil?
      end
    end

    # Pattern for parsing one /proc/<pid>/maps row.
    LINE_PATTERN = /\A(?<start>[0-9a-f]+)-(?<finish>[0-9a-f]+)\s+(?<perms>[rwxps-]{4})\s+(?<offset>[0-9a-f]+)\s+(?<device>[0-9a-f]+:[0-9a-f]+)\s+(?<inode>\d+)\s*(?<path>.*)\z/.freeze

    module_function

    # Reads and parses /proc/<pid>/maps.
    #
    # @param pid [Integer]
    # @return [Array<Mapping>]
    def read(pid)
      parse(File.read("/proc/#{Integer(pid)}/maps"))
    end

    # Parses full /proc maps content.
    #
    # @param content [String]
    # @return [Array<Mapping>]
    def parse(content)
      content.each_line(chomp: true).filter_map do |line|
        next if line.empty?

        parse_line(line)
      end
    end

    # Parses one /proc maps line.
    #
    # @param line [String]
    # @return [Mapping]
    # @raise [ArgumentError]
    def parse_line(line)
      match = LINE_PATTERN.match(line)
      raise ArgumentError, "invalid /proc maps line: #{line.inspect}" unless match

      pathname = match[:path].strip
      pathname = nil if pathname.empty?

      Mapping.new(
        start_addr: match[:start].to_i(16),
        end_addr: match[:finish].to_i(16),
        permissions: match[:perms],
        offset: match[:offset].to_i(16),
        device: match[:device],
        inode: match[:inode].to_i,
        pathname: pathname
      )
    end
  end
end

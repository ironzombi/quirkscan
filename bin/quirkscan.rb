#!/usr/bin/env ruby
# QuirkScan v0 - Nullstep x ZeroTrace
# A tiny host recon & config checker

require 'socket'
require 'optparse'

module QuirkScan
  COMMON_PORTS = [22, 80, 443, 3389, 53, 25, 110, 143, 587, 993, 995].freeze

  # ---------- Host info ----------
  class HostInfo
    def self.run
      puts "[*] Host information"
      puts "    Hostname : #{`hostname`.strip rescue 'unknown'}"
      puts "    OS       : #{`uname -s`.strip rescue 'unknown'}"
      puts "    Kernel   : #{`uname -r`.strip rescue 'unknown'}"
      puts "    Arch     : #{`uname -m`.strip rescue 'unknown'}"
      puts
    end
  end

  # ---------- Port scanner ----------
  class PortScanner
    def initialize(target, ports, timeout: 0.3)
      @target  = target
      @ports   = ports
      @timeout = timeout
    end

    def run
      puts "[*] Port scan on #{@target}"
      open_ports = []

      @ports.each do |port|
        begin
          Socket.tcp(@target, port, connect_timeout: @timeout) do |sock|
            sock.close
          end
          puts "    [+] #{port}/tcp OPEN"
          open_ports << port
        rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, SocketError, IOError
          # closed or unreachable, ignore
        rescue => e
          puts "    [!] Error on port #{port}: #{e.class} #{e.message}"
        end
      end

      puts "    Open ports: #{open_ports.any? ? open_ports.join(', ') : 'none detected'}"
      puts
    end
  end

  # ---------- SSH config checker ----------
  class SSHChecker
    BAD_FLAGS = {
      /PermitRootLogin\s+yes/i        => "Root login via SSH is allowed",
      /PasswordAuthentication\s+yes/i => "Password authentication enabled (consider keys only)",
      /PermitEmptyPasswords\s+yes/i   => "Empty passwords allowed (VERY bad)"
    }.freeze

    def initialize(path = '/etc/ssh/sshd_config')
      @path = path
    end

    def run
      puts "[*] SSH config check (#{@path})"

      unless File.exist?(@path)
        puts "    [!] File not found"
        puts
        return
      end

      content = File.read(@path)
      issues = []

      BAD_FLAGS.each do |regex, message|
        if content.match?(regex)
          issues << "    [!] #{message}"
        end
      end

      if issues.empty?
        puts "    [+] No obvious bad flags found (for the few we check)."
      else
        issues.each { |line| puts line }
      end

      puts
    end
  end
end

# ---------- CLI wrapper ----------

options = {
  target: '127.0.0.1',
  ports:  nil,
  ssh_config: '/etc/ssh/sshd_config',
  mode: :all
}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: quirkscan.rb [options]\n\n" \
                "Examples:\n" \
                "  ruby quirkscan.rb                      # run all checks on localhost\n" \
                "  ruby quirkscan.rb -t 192.168.1.10      # scan that host\n" \
                "  ruby quirkscan.rb --ports 22,80,443    # custom ports\n" \
                "  ruby quirkscan.rb --mode ssh           # only SSH config check\n\n"

  opts.on("-t", "--target HOST", "Target host for port scan (default: 127.0.0.1)") do |t|
    options[:target] = t
  end

  opts.on("--ports LIST", "Comma-separated ports or ranges, e.g. 22,80,1000-1010") do |list|
    parsed = []
    list.split(',').each do |part|
      if part.include?('-')
        start_s, stop_s = part.split('-', 2)
        parsed.concat((start_s.to_i)..(stop_s.to_i))
      else
        parsed << part.to_i
      end
    end
    options[:ports] = parsed.uniq.sort
  end

  opts.on("--ssh-config PATH", "Path to sshd_config (default: /etc/ssh/sshd_config)") do |path|
    options[:ssh_config] = path
  end

  opts.on("--mode MODE", "What to run: all, host, ports, ssh") do |m|
    options[:mode] = m.to_sym
  end

  opts.on("-h", "--help", "Show this help") do
    puts opts
    exit
  end
end

begin
  parser.parse!
rescue OptionParser::InvalidOption => e
  warn e.message
  puts parser
  exit 1
end

# ---------- Run selected mode(s) ----------

case options[:mode]
when :all
  QuirkScan::HostInfo.run
  QuirkScan::PortScanner.new(
    options[:target],
    options[:ports] || QuirkScan::COMMON_PORTS
  ).run
  QuirkScan::SSHChecker.new(options[:ssh_config]).run

when :host
  QuirkScan::HostInfo.run

when :ports
  QuirkScan::PortScanner.new(
    options[:target],
    options[:ports] || QuirkScan::COMMON_PORTS
  ).run

when :ssh
  QuirkScan::SSHChecker.new(options[:ssh_config]).run

else
  puts "[!] Unknown mode: #{options[:mode]}"
  puts parser
  exit 1
end


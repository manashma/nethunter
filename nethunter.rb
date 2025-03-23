#!/usr/bin/env ruby

require 'optparse'
require 'json'
require 'socket'
require 'net/http'
require 'uri'
require 'fileutils'
require 'colorize'
require 'time' # Added missing Time.parse requirement
require 'timeout' # For more reliable scanning timeouts
require 'concurrent' # For parallel scanning

class NetHunter
  VERSION = '1.1.0'
  
  def initialize
    @config_path = File.join(Dir.pwd, 'config.json')
    @payloads_dir = File.join(Dir.pwd, 'payloads')
    @exploits_dir = File.join(Dir.pwd, 'exploits')
    @output_dir = File.join(Dir.pwd, 'output')
    @scan_results = {}
    
    # Create required directories if they don't exist
    [
      @payloads_dir, 
      @exploits_dir, 
      @output_dir
    ].each do |dir|
      FileUtils.mkdir_p(dir) unless Dir.exist?(dir)
    end
    
    # Create default config if it doesn't exist
    create_default_config unless File.exist?(@config_path)
    
    @config = load_config
  end
  
  def create_default_config
    default_config = {
      "scan_timeout": 5,
      "default_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5900, 8080],
      "exploit_timeout": 10,
      "user_agent": "NetHunter/#{VERSION}",
      "verbose": false,
      "threads": 10,
      "aggressive_scan": false,
      "last_scan": Time.now.to_s
    }
    
    File.write(@config_path, JSON.pretty_generate(default_config))
    puts "[+] Created default configuration file at #{@config_path}".green
  end
  
  def load_config
    JSON.parse(File.read(@config_path))
  end
  
  def save_config
    File.write(@config_path, JSON.pretty_generate(@config))
  end
  
  def banner
    puts <<-BANNER
    ███╗   ██╗███████╗████████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ████╗  ██║██╔════╝╚══██╔══╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██╔██╗ ██║█████╗     ██║   ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██║╚██╗██║██╔══╝     ██║   ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║ ╚████║███████╗   ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                         v#{VERSION}
    
    An Advanced Network Vulnerability Scanner
    BANNER
  end
  
  def parse_options
    options = {}
    
    parser = OptionParser.new do |opts|
      opts.banner = "Usage: nethunter.rb [options]"
      
      opts.on("-t", "--target TARGET", "Target IP address or hostname to scan") do |target|
        options[:target] = target
      end
      
      opts.on("-r", "--range IP_RANGE", "Target IP range (e.g., 192.168.1.1-192.168.1.254)") do |range|
        options[:range] = range
      end
      
      opts.on("-p", "--ports PORT_RANGE", "Port range to scan (e.g., 1-100 or 80,443,8080)") do |ports|
        if ports.include?("-")
          start_port, end_port = ports.split("-").map(&:to_i)
          options[:ports] = (start_port..end_port).to_a
        else
          options[:ports] = ports.split(",").map(&:to_i)
        end
      end
      
      opts.on("--payload PAYLOAD_NAME", "Custom payload to use") do |payload|
        options[:payload] = payload
      end
      
      opts.on("-o", "--output FILENAME", "Output scan results to file") do |filename|
        options[:output] = filename
      end
      
      opts.on("-v", "--verbose", "Enable verbose output") do
        options[:verbose] = true
      end
      
      opts.on("--exploit EXPLOIT_NAME", "Use a specific exploit") do |exploit|
        options[:exploit] = exploit
      end
      
      opts.on("--list-payloads", "List available payloads") do
        options[:list_payloads] = true
      end
      
      opts.on("--list-exploits", "List available exploits") do
        options[:list_exploits] = true
      end
      
      opts.on("--pentest", "Run a direct pentest using chosen payload") do
        options[:pentest] = true
      end
      
      opts.on("--timeout SECONDS", Integer, "Set scan timeout") do |timeout|
        options[:timeout] = timeout
      end
      
      opts.on("--threads NUM", Integer, "Number of concurrent scanning threads") do |threads|
        options[:threads] = threads
      end
      
      opts.on("--aggressive", "Enable aggressive scanning (service detection, version detection)") do
        options[:aggressive] = true
      end
      
      opts.on("--service-scan", "Perform service detection on open ports") do
        options[:service_scan] = true
      end
      
      opts.on("--vuln-scan", "Scan for common vulnerabilities on detected services") do
        options[:vuln_scan] = true
      end
      
      opts.on_tail("-h", "--help", "Show this help message") do
        puts opts
        exit
      end
      
      opts.on_tail("--version", "Show version") do
        puts "NetHunter v#{VERSION}"
        exit
      end
    end
    
    parser.parse!
    
    options
  end
  
  def list_payloads
    puts "[*] Available Payloads:".blue
    
    payloads = Dir.glob(File.join(@payloads_dir, "*.rb"))
    if payloads.empty?
      puts "  No payloads found. Add custom payloads to the 'payloads' directory.".yellow
    else
      payloads.each do |payload|
        name = File.basename(payload, ".rb")
        description = extract_description(payload)
        puts "  - #{name}: #{description}".green
      end
    end
  end
  
  def list_exploits
    puts "[*] Available Exploits:".blue
    
    exploits = Dir.glob(File.join(@exploits_dir, "*.rb"))
    if exploits.empty?
      puts "  No exploits found. Add exploits to the 'exploits' directory.".yellow
    else
      exploits.each do |exploit|
        name = File.basename(exploit, ".rb")
        description = extract_description(exploit)
        puts "  - #{name}: #{description}".green
      end
    end
  end
  
  def extract_description(file_path)
    content = File.read(file_path)
    if content.match(/# Description: (.+)$/)
      return $1.strip
    end
    return "No description available"
  end
  
  def expand_ip_range(range)
    if range.include?('-')
      start_ip, end_ip = range.split('-')
      start_segments = start_ip.split('.').map(&:to_i)
      end_segments = end_ip.split('.').map(&:to_i)
      
      # Handle simplified range like 192.168.1.1-254
      if start_segments.size == 4 && end_segments.size == 1
        start_segments[3] = 1
        end_segments = start_segments[0..2] + [end_segments[0]]
      end
      
      start_num = start_segments[0] << 24 | start_segments[1] << 16 | start_segments[2] << 8 | start_segments[3]
      end_num = end_segments[0] << 24 | end_segments[1] << 16 | end_segments[2] << 8 | end_segments[3]
      
      (start_num..end_num).map do |num|
        "#{(num >> 24) & 255}.#{(num >> 16) & 255}.#{(num >> 8) & 255}.#{num & 255}"
      end
    elsif range.include?('/')
      # Handle CIDR notation
      require 'ipaddr'
      ips = []
      IPAddr.new(range).to_range.each do |ip|
        ips << ip.to_s
      end
      ips
    else
      [range]
    end
  end
  
  def port_scan(target, ports, timeout = 5, verbose = false, threads = 10)
    puts "[*] Starting port scan on #{target}...".blue
    open_ports = []
    mutex = Mutex.new
    
    port_batches = ports.each_slice([ports.size, threads].min).to_a
    
    port_batches.each do |batch|
      threads = batch.map do |port|
        Thread.new do
          begin
            Timeout.timeout(timeout) do
              socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM)
              socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
              
              sockaddr = Socket.sockaddr_in(port, target)
              
              begin
                socket.connect_nonblock(sockaddr)
              rescue IO::WaitWritable
                # Port is potentially open, wait for confirmation
                if IO.select(nil, [socket], nil, timeout)
                  mutex.synchronize do
                    open_ports << port
                    service = identify_service(port)
                    puts "  [+] Port #{port} is open (#{service})".green if verbose
                  end
                end
              rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH
                # Port is closed or host unreachable
              end
              
              socket.close if socket && !socket.closed?
            end
          rescue Timeout::Error
            # Timeout on this port, move on
          rescue => e
            puts "  [-] Error scanning port #{port}: #{e.message}".red if verbose
          end
        end
      end
      
      threads.each(&:join)
    end
    
    puts "[+] Scan complete. Found #{open_ports.length} open ports.".green
    open_ports
  end
  
  def identify_service(port)
    services = {
      21 => "FTP",
      22 => "SSH",
      23 => "Telnet",
      25 => "SMTP",
      53 => "DNS",
      80 => "HTTP",
      110 => "POP3",
      135 => "MSRPC",
      139 => "NetBIOS",
      143 => "IMAP",
      443 => "HTTPS",
      445 => "SMB",
      1433 => "MSSQL",
      3306 => "MySQL",
      3389 => "RDP",
      5900 => "VNC",
      8080 => "HTTP-Proxy",
      8443 => "HTTPS-Alt",
      6379 => "Redis",
      27017 => "MongoDB",
      9200 => "Elasticsearch",
      5432 => "PostgreSQL",
      2049 => "NFS",
      161 => "SNMP"
    }
    
    services[port] || "Unknown"
  end
  
  def service_scan(target, port, timeout = 5)
    service_name = identify_service(port)
    service_info = {
      name: service_name,
      version: nil,
      banner: nil,
      details: {}
    }
    
    case service_name
    when "HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt"
      protocol = (service_name == "HTTPS" || service_name == "HTTPS-Alt") ? "https" : "http"
      begin
        uri = URI.parse("#{protocol}://#{target}:#{port}/")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (protocol == "https")
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = timeout
        http.read_timeout = timeout
        
        response = http.get('/')
        
        service_info[:version] = response['server'] if response['server']
        service_info[:banner] = response['server'] if response['server']
        service_info[:details][:status] = response.code
        service_info[:details][:headers] = response.to_hash
      rescue => e
        # Non-fatal error
      end
    when "SSH"
      begin
        require 'net/ssh'
        banner = nil
        Net::SSH.start(target, "invalid_user", password: "invalid_password", auth_methods: ["none"], non_interactive: true, timeout: timeout) rescue banner = $!.message
        if banner && banner.include?("banner:")
          service_info[:banner] = banner.split("banner:").last.strip
          if service_info[:banner] =~ /SSH-\d+\.\d+-(.+)/
            service_info[:version] = $1
          end
        end
      rescue LoadError
        # Net::SSH library not available
      rescue => e
        # Non-fatal error
      end
    when "FTP"
      begin
        require 'net/ftp'
        ftp = Net::FTP.new
        ftp.connect(target, port, timeout)
        service_info[:banner] = ftp.welcome
        if service_info[:banner] =~ /(.+) Server/
          service_info[:version] = $1
        end
        ftp.close
      rescue => e
        # Attempt to get banner without full connection
        begin
          socket = TCPSocket.new(target, port)
          banner = socket.gets.to_s.strip
          service_info[:banner] = banner if banner && !banner.empty?
          socket.close
        rescue => e
          # Non-fatal error
        end
      end
    when "SMTP"
      begin
        require 'net/smtp'
        smtp = Net::SMTP.new(target, port)
        smtp.open_timeout = timeout
        smtp.start('localhost')
        service_info[:banner] = smtp.instance_variable_get(:@resp).to_s
        smtp.finish
      rescue => e
        # Attempt to get banner without full connection
        begin
          socket = TCPSocket.new(target, port)
          banner = socket.gets.to_s.strip
          service_info[:banner] = banner if banner && !banner.empty?
          socket.close
        rescue => e
          # Non-fatal error
        end
      end
    else
      # Generic banner grabbing for other services
      begin
        socket = TCPSocket.new(target, port)
        socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [timeout, 0].pack('l_2'))
        socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, [timeout, 0].pack('l_2'))
        socket.print("\r\n")
        banner = socket.gets.to_s.strip
        service_info[:banner] = banner if banner && !banner.empty?
        socket.close
      rescue => e
        # Non-fatal error
      end
    end
    
    service_info
  end
  
  def run_payload(payload_name, target, open_ports, options)
    payload_path = File.join(@payloads_dir, "#{payload_name}.rb")
    
    unless File.exist?(payload_path)
      puts "[-] Payload '#{payload_name}' not found!".red
      return nil
    end
    
    puts "[*] Running payload: #{payload_name}".blue
    
    # Load the payload file
    begin
      # Remove old constants if they exist to avoid warnings
      if Object.const_defined?(payload_name.split('_').map(&:capitalize).join)
        Object.send(:remove_const, payload_name.split('_').map(&:capitalize).join.to_sym)
      end
      
      load payload_path
      
      # Create a payload instance and run it
      payload_class_name = payload_name.split('_').map(&:capitalize).join
      payload_class = Object.const_get(payload_class_name)
      payload = payload_class.new
      
      return payload.run(target, open_ports, options)
    rescue => e
      puts "[-] Error running payload: #{e.message}".red
      puts e.backtrace.join("\n").red if options[:verbose]
      return nil
    end
  end
  
  def run_exploit(exploit_name, target, port, options)
    exploit_path = File.join(@exploits_dir, "#{exploit_name}.rb")
    
    unless File.exist?(exploit_path)
      puts "[-] Exploit '#{exploit_name}' not found!".red
      return false
    end
    
    puts "[*] Running exploit: #{exploit_name} against #{target}:#{port}".blue
    
    # Load the exploit file
    begin
      # Remove old constants if they exist to avoid warnings
      if Object.const_defined?(exploit_name.split('_').map(&:capitalize).join)
        Object.send(:remove_const, exploit_name.split('_').map(&:capitalize).join.to_sym)
      end
      
      load exploit_path
      
      # Create an exploit instance and run it
      exploit_class_name = exploit_name.split('_').map(&:capitalize).join
      exploit_class = Object.const_get(exploit_class_name)
      exploit = exploit_class.new
      
      success = exploit.run(target, port, options)
      
      if success
        puts "[+] Exploit successful!".green
      else
        puts "[-] Exploit failed.".red
      end
      
      return success
    rescue => e
      puts "[-] Error running exploit: #{e.message}".red
      puts e.backtrace.join("\n").red if options[:verbose]
      return false
    end
  end
  
  def check_vulnerabilities(target, port, service_info)
    vulnerabilities = []
    
    case service_info[:name]
    when "HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt"
      # Check for common web vulnerabilities
      protocol = (service_info[:name] == "HTTPS" || service_info[:name] == "HTTPS-Alt") ? "https" : "http"
      uri = URI.parse("#{protocol}://#{target}:#{port}/")
      
      # Check for common sensitive paths
      sensitive_paths = [
        "/admin", "/login", "/wp-admin", "/phpmyadmin", "/manager/html", 
        "/.git", "/.env", "/api", "/v1", "/v2", "/swagger", "/actuator",
        "/server-status", "/server-info"
      ]
      
      sensitive_paths.each do |path|
        begin
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = (protocol == "https")
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          http.open_timeout = 3
          http.read_timeout = 3
          
          response = http.get(path)
          
          if response.code.to_i < 400
            vulnerabilities << {
              type: "Exposed Path",
              path: path,
              severity: "Medium",
              details: "Potentially sensitive path #{path} is accessible (Status: #{response.code})"
            }
          end
        rescue => e
          # Non-fatal error
        end
      end
      
      # Check for outdated server software
      if service_info[:banner]
        common_outdated = {
          "Apache/1" => "Outdated Apache 1.x",
          "Apache/2.0" => "Outdated Apache 2.0.x",
          "Apache/2.2" => "Potentially outdated Apache 2.2.x",
          "nginx/1.0" => "Outdated Nginx 1.0.x",
          "nginx/1.1" => "Outdated Nginx 1.1.x",
          "Microsoft-IIS/5" => "Outdated IIS 5.x",
          "Microsoft-IIS/6" => "Outdated IIS 6.x",
          "PHP/5.2" => "Outdated PHP 5.2.x",
          "PHP/5.3" => "Outdated PHP 5.3.x",
          "PHP/5.4" => "Outdated PHP 5.4.x"
        }
        
        common_outdated.each do |pattern, description|
          if service_info[:banner].include?(pattern)
            vulnerabilities << {
              type: "Outdated Software",
              severity: "High",
              details: "#{description} detected: #{service_info[:banner]}"
            }
          end
        end
      end
      
    when "SSH"
      # Check for weak SSH configurations
      if service_info[:banner]
        if service_info[:banner].include?("SSH-1") || service_info[:banner].include?("SSH-1.99")
          vulnerabilities << {
            type: "Weak Protocol",
            severity: "High",
            details: "SSH server supports outdated SSH1 protocol: #{service_info[:banner]}"
          }
        end
        
        weak_ciphers = ["arcfour", "blowfish-cbc", "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"]
        weak_ciphers.each do |cipher|
          if service_info[:banner].include?(cipher)
            vulnerabilities << {
              type: "Weak Cipher",
              severity: "Medium",
              details: "SSH server may support weak cipher: #{cipher}"
            }
          end
        end
      end
      
    when "FTP"
      # Check for anonymous FTP
      begin
        require 'net/ftp'
        ftp = Net::FTP.new
        ftp.connect(target, port, 5)
        ftp.login("anonymous", "anonymous@example.com")
        
        vulnerabilities << {
          type: "Anonymous Access",
          severity: "High",
          details: "FTP server allows anonymous access"
        }
        
        # Check for writable directories
        dirs = ftp.list
        ftp.close
      rescue => e
        # Failed to login anonymously, which is good
      end
      
    when "SMB"
      # Check for SMB vulnerabilities
      if service_info[:version] && service_info[:version].include?("1.0")
        vulnerabilities << {
          type: "Outdated Protocol",
          severity: "Critical",
          details: "SMBv1 protocol in use, potentially vulnerable to EternalBlue (MS17-010)"
        }
      end
    end
    
    vulnerabilities
  end
  
  def save_output(filename, data)
    output_path = File.join(@output_dir, filename)
    
    File.write(output_path, JSON.pretty_generate(data))
    puts "[+] Results saved to #{output_path}".green
  end
  
  def run
    banner
    options = parse_options
    
    if options[:list_payloads]
      list_payloads
      return
    end
    
    if options[:list_exploits]
      list_exploits
      return
    end
    
    unless options[:target] || options[:range]
      puts "[-] Target is required. Use -t/--target or -r/--range to specify a target.".red
      return
    end
    
    # Update config with options
    @config["verbose"] = options[:verbose] if options.key?(:verbose)
    @config["scan_timeout"] = options[:timeout] if options[:timeout]
    @config["threads"] = options[:threads] if options[:threads]
    @config["aggressive_scan"] = options[:aggressive] if options.key?(:aggressive)
    @config["last_scan"] = Time.now.to_s
    save_config

    # Initialize scan start time for duration calculation
    scan_start_time = Time.now
    
    # Use specified ports or default ports from config
    ports = options[:ports] || @config["default_ports"]
    threads = options[:threads] || @config["threads"] || 10
    timeout = options[:timeout] || @config["scan_timeout"] || 5
    
    targets = []
    if options[:range]
      puts "[*] Expanding IP range #{options[:range]}...".blue
      targets = expand_ip_range(options[:range])
      puts "[+] Found #{targets.size} targets in range".green
    else
      targets = [options[:target]]
    end
    
    all_results = {}
    
    targets.each do |target|
      # Perform port scan
      puts "[*] Scanning target: #{target}".blue
      open_ports = port_scan(target, ports, timeout, @config["verbose"], threads)
      
      # Create results hash
      results = {
        target: target,
        timestamp: Time.now.to_s,
        open_ports: open_ports,
        services: {},
        vulnerabilities: [],
        scan_duration: (Time.now - scan_start_time).round(2)
      }
      
      # Perform service detection if requested or aggressive mode
      if options[:service_scan] || options[:aggressive] || @config["aggressive_scan"]
        puts "[*] Performing service detection on #{open_ports.size} open ports...".blue
        
        open_ports.each do |port|
          service_info = service_scan(target, port, timeout)
          results[:services][port] = service_info
          puts "  [+] Port #{port}: #{service_info[:name]} #{service_info[:version] || ''}".green if @config["verbose"]
          puts "      Banner: #{service_info[:banner]}".green if @config["verbose"] && service_info[:banner]
        end
      end
      
      # Perform vulnerability scan if requested
      if options[:vuln_scan] || options[:aggressive] || @config["aggressive_scan"]
        if results[:services].empty?
          # Need to perform service detection first
          puts "[*] Performing service detection for vulnerability scanning...".blue
          open_ports.each do |port|
            service_info = service_scan(target, port, timeout)
            results[:services][port] = service_info
          end
        end
        
        puts "[*] Scanning for vulnerabilities...".blue
        results[:services].each do |port, service_info|
          port_vulns = check_vulnerabilities(target, port, service_info)
          
          if !port_vulns.empty?
            results[:vulnerabilities].concat(port_vulns)
            port_vulns.each do |vuln|
              puts "  [!] Found vulnerability on port #{port}: #{vuln[:type]} (#{vuln[:severity]})".yellow
              puts "      #{vuln[:details]}".yellow if @config["verbose"]
            end
          end
        end
      end
      
      # Run payload if specified
      if options[:payload]
        payload_results = run_payload(options[:payload], target, open_ports, options)
        results[:payload_results] = payload_results if payload_results
      end
      
      # Run exploit if specified
      if options[:exploit] && !open_ports.empty?
        target_port = open_ports.first
        exploit_success = run_exploit(options[:exploit], target, target_port, options)
        results[:exploit_success] = exploit_success
      end
      
      # Run pentest if specified
      if options[:pentest] && options[:payload]
        puts "[*] Running direct pentest using payload: #{options[:payload]}".blue
        
        if !open_ports.empty?
          results[:pentest_results] = run_payload(options[:payload], target, open_ports, options.merge({pentest: true}))
        else
          puts "[-] Cannot run pentest: No open ports found.".red
        end
      end
      
      all_results[target] = results
      @scan_results[target] = results
    end
    
    # Calculate total scan duration
    scan_duration = (Time.now - scan_start_time).round(2)
    
    # Create summary
    summary = {
      total_targets: targets.size,
      targets_with_open_ports: all_results.count { |_, r| !r[:open_ports].empty? },
      total_open_ports: all_results.sum { |_, r| r[:open_ports].size },
      total_vulnerabilities: all_results.sum { |_, r| r[:vulnerabilities].size },
      scan_duration: scan_duration,
      timestamp: Time.now.to_s
    }
    
    # Add summary to results
    final_results = {
      summary: summary,
      targets: all_results
    }
    
    # Save output if specified
    if options[:output]
      save_output(options[:output], final_results)
    else
      # Print summary
      puts "\n[+] Scan Summary:".green
      puts "  Targets scanned: #{summary[:total_targets]}".green
      puts "  Targets with open ports: #{summary[:targets_with_open_ports]}".green
      puts "  Total open ports: #{summary[:total_open_ports]}".green
      puts "  Total vulnerabilities: #{summary[:total_vulnerabilities]}".green
      puts "  Scan duration: #{summary[:scan_duration]} seconds".green
      
      # Print detailed results if verbose
      if @config["verbose"]
        puts "\n[+] Detailed Results:".green
        puts JSON.pretty_generate(final_results)
      end
    end
  end
end

# Install gem if not already available
begin
  require 'concurrent'
rescue LoadError
  puts "[*] Installing required gem: concurrent-ruby".blue
  system("gem install concurrent-ruby")
  require 'concurrent'
end

if __FILE__ == $0
  nethunter = NetHunter.new
  nethunter.run
end

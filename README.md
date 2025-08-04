# SCOPEX - Advanced Domain Reconnaissance Tool for Red Teaming

SCOPEX is a comprehensive, CLI-based domain reconnaissance tool designed specifically for red teaming operations. It provides extensive passive reconnaissance capabilities, vulnerability detection, and security analysis to help security professionals identify attack surfaces and potential security weaknesses.

## Key Features

### Core Reconnaissance Modules
- **Subdomain Enumeration**: Passive discovery using multiple sources (crt.sh, DNS brute-forcing, public APIs)
- **DNS Resolution**: Comprehensive DNS record analysis (A, AAAA, MX, TXT, DMARC, SPF, SOA, PTR)
- **SSL Certificate Inspection**: Certificate analysis, expiry detection, and vulnerability assessment
- **WHOIS Lookup**: Domain registration information and security analysis
- **Service Detection**: HTTP/HTTPS status codes and server information for subdomains
- **Robots.txt & Sitemap Analysis**: Path discovery and sensitive endpoint identification
- **Technology Stack Fingerprinting**: Web server, framework, and technology identification
- **Vulnerability Checking**: Security header analysis, misconfiguration detection

### Advanced Features
- **File Extraction**: Extract specific file types (e.g., .txt, .pdf, .pptx) from target domains
- **OWASP Top 10 Checks**: Automated checks for common web application vulnerabilities
- **Plugin Architecture**: Extensible plugin system for custom modules
- **Risk Scoring**: Automated risk assessment based on findings
- **Multiple Output Formats**: JSON (machine-readable) and TXT (human-readable) reports
- **Stealth Operations**: Custom user-agents, request throttling, and OpSec features
- **Comprehensive Logging**: Silent logging for operational security

### Built-in Plugins
- **WAF Detector**: Identifies Web Application Firewalls and suggests bypass techniques
- **Shodan Integration**: Enhanced intelligence gathering (requires API key)

## Installation

### Prerequisites
- Python 3.11 or higher
- pip3 package manager

### Quick Installation
```bash
# To set up the project, follow these steps:

# Clone the repository:
git clone https://github.com/rizul0x01/scopex-domain-reconnaisance.git ScopeX

# Clone or download the scopex directory
cd ScopeX

# Install dependencies: It is highly recommended to use a Python virtual environment to avoid conflicts with your system's Python packages.

# Create a virtual environment
python3 -m venv scopex_myenv

# Activate the virtual environment
source scopex_myenv/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Make the main script executable
chmod +x main.py
```

### Dependencies
- `requests` - HTTP client library
- `dnspython` - DNS toolkit
- `python-whois` - WHOIS client
- `beautifulsoup4` - HTML parsing
- `pyyaml` - YAML configuration support
- `colorama` - Terminal colors
- `shodan` - Shodan API integration

## Usage

### Basic Usage
```bash
# Basic reconnaissance scan
python3 main.py -d example.com

# Deep scan with comprehensive enumeration
python3 main.py -d example.com --deep

# Fast scan (skips time-consuming modules)
python3 main.py -d example.com --fast

# Verbose output for debugging
python3 main.py -d example.com --verbose
```

### Advanced Usage
```bash
# Custom output location
python3 main.py -d example.com --out /path/to/report.json

# Run with plugins
python3 main.py -d example.com --plugins waf_detector,shodan_lookup

# Combined options
python3 main.py -d example.com --deep --plugins waf_detector --verbose
```

### Command Line Options
```
-d, --domain        Target domain (required)
--deep             Enable deep reconnaissance (slower but comprehensive)
--fast             Fast mode - skip time-consuming modules
--out              Output file path for JSON report
--plugins          Comma-separated list of plugins to run
--verbose, -v      Enable verbose output
--log-file         Custom log file path
--extract-files    Comma-separated list of file extensions to extract (e.g., pdf,txt,pptx)
--owasp            Enable OWASP Top 10 vulnerability checks
```

## Security & OpSec

### Stealth Features
- **User-Agent Rotation**: Randomized browser identification
- **Request Throttling**: Configurable delays between requests
- **Silent Logging**: All activities logged to file, not console
- **Error Handling**: Graceful failure without revealing tool usage

### Operational Security
- **No Banner**: Tool doesn't identify itself in requests
- **Passive Techniques**: Primarily uses public data sources
- **Configurable Timeouts**: Avoid hanging on unresponsive targets
- **Rate Limiting**: Prevents overwhelming target infrastructure

## Red Team Focus

### Attack Surface Discovery
- **Subdomain Enumeration**: Find forgotten or development subdomains
- **Technology Identification**: Identify outdated or vulnerable software
- **Path Discovery**: Locate admin interfaces and sensitive directories
- **Certificate Analysis**: Find certificate transparency log entries

### Vulnerability Assessment
- **Security Headers**: Identify missing security controls
- **Misconfigurations**: Detect common security misconfigurations
- **Information Disclosure**: Find exposed sensitive information
- **Risk Scoring**: Prioritize findings based on security impact

## Performance

### Optimization Features
- **Concurrent Requests**: Asynchronous HTTP requests where possible
- **Intelligent Caching**: Avoid duplicate requests
- **Configurable Depth**: Balance speed vs. comprehensiveness
- **Resource Limits**: Prevent excessive resource consumption

### Benchmarks
- **Basic Scan**: ~30-60 seconds for typical domain
- **Deep Scan**: ~2-5 minutes with comprehensive enumeration
- **Fast Scan**: ~15-30 seconds with essential modules only

## Examples

### Basic Reconnaissance
```bash
# Quick assessment of a target
python3 main.py -d target.com --fast

# Results: Basic subdomain enum, DNS records, WHOIS info
# Time: ~30 seconds
# Risk Score: Calculated based on findings
```

### Comprehensive Assessment
```bash
# Full reconnaissance with all modules
python3 main.py -d target.com --deep --plugins waf_detector,shodan_lookup

# Results: Complete attack surface mapping
# Time: ~5 minutes
# Includes: All subdomains, tech stack, vulnerabilities, WAF detection
```

### Automated Integration
```bash
# Generate machine-readable output for automation
python3 main.py -d target.com --out /tmp/target_recon.json

# Parse results with jq
cat /tmp/target_recon.json | jq '.vulnerabilities[]'
```

## Contributing

### Development Setup
```bash
# Clone repository
git clone <repository_url>
cd scopex

# Install development dependencies
pip3 install -r requirements.txt

# Run tests
python3 -m pytest tests/
```

### Adding New Modules
1. Create module in `core/` directory
2. Implement main function with standard interface
3. Add import to `main.py`
4. Update documentation

### Plugin Development
1. Create plugin file in `plugins/` directory
2. Implement `run_plugin()` function
3. Test with `--plugins` flag
4. Document plugin functionality

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

SCOPEX is designed for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any targets. The developers assume no liability for misuse of this tool.

## Resources

### Related Tools
- **Amass**: OWASP subdomain enumeration tool
- **Subfinder**: Fast passive subdomain discovery
- **Recon-ng**: Full-featured reconnaissance framework
- **Nmap**: Network discovery and security auditing

### Learning Resources
- **OWASP Testing Guide**: Web application security testing methodology
- **PTES**: Penetration Testing Execution Standard
- **Red Team Field Manual**: Tactical reference for red team operations

---

**SCOPEX** - Comprehensive Domain Reconnaissance for Red Team Operations

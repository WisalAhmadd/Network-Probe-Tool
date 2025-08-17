# Network-Probe-Tool

Features:

1. Host Discovery
Ping sweep to identify live hosts on a network
Supports CIDR notation (e.g., 192.168.1.0/24)

2. Port Scanning
TCP and UDP port scanning
Configurable port ranges
Multi-threaded for efficiency

3. Service Detection
Banner grabbing to identify services
HTTP server detection
Common service identification (SSH, FTP, SMTP, etc.)

4. Security Assessment
Basic vulnerability checks
Identification of potentially insecure services
Security recommendations

5. Reporting
JSON output for integration with other tools
Comprehensive scan reports
Timestamped results

Usage Examples:  (BASH)
# Scan a single host
python network_probe.py -t {ip_address}
or
python network_probe.py -t {ip_address}

# Scan an entire network
python network_probe.py -n {ip_address}/24

# Just do a ping sweep
python network_probe.py -n {ip_address}/24 --ping-only

# Save results to file
python network_probe.py -t {ip_address} -o scan_results.json


Important Security Notes:
Only use this tool on networks you own or have explicit written permission to test
Unauthorized network scanning may violate laws and policies
Always ensure you have proper authorization before running
Use responsibly for legitimate security assessments


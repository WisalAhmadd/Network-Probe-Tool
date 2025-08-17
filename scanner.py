#!/usr/bin/env python3
"""
IMPORTANT: Only use on networks you own or have explicit permission to test.
"""

import socket
import threading
import subprocess
import ipaddress
import argparse
import time
import sys
from datetime import datetime
import json

class NetworkProbe:
    def __init__(self):
        self.results = {
            'scan_time': datetime.now().isoformat(),
            'targets': [],
            'open_ports': {},
            'services': {},
            'host_discovery': []
        }
        
    def ping_sweep(self, network):
        """Perform ping sweep to discover live hosts"""
        print(f"[+] Starting ping sweep on {network}")
        live_hosts = []
        
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            threads = []
            
            def ping_host(ip):
                try:
                    # Use ping command based on OS
                    if sys.platform.startswith('win'):
                        cmd = ['ping', '-n', '1', '-w', '1000', str(ip)]
                    else:
                        cmd = ['ping', '-c', '1', '-W', '1', str(ip)]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        live_hosts.append(str(ip))
                        print(f"[+] Host discovered: {ip}")
                except:
                    pass
            
            # Limit to first 254 hosts to avoid overwhelming
            hosts_to_scan = list(net.hosts())[:254]
            for ip in hosts_to_scan:
                thread = threading.Thread(target=ping_host, args=(ip,))
                threads.append(thread)
                thread.start()
                
                # Limit concurrent threads
                if len(threads) >= 50:
                    for t in threads:
                        t.join()
                    threads = []
            
            # Wait for remaining threads
            for t in threads:
                t.join()
                
        except Exception as e:
            print(f"[-] Error in ping sweep: {e}")
            
        self.results['host_discovery'] = live_hosts
        return live_hosts
    
    def port_scan(self, target, ports=None, scan_type='tcp'):
        """Perform port scanning on target"""
        if ports is None:
            # Common ports for quick scan
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1723, 3389, 5900, 8080]
        
        print(f"[+] Starting {scan_type.upper()} port scan on {target}")
        open_ports = []
        
        def scan_port(port):
            try:
                if scan_type.lower() == 'tcp':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(port)
                        print(f"[+] {target}:{port} - OPEN")
                    sock.close()
                elif scan_type.lower() == 'udp':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1)
                    try:
                        sock.sendto(b'', (target, port))
                        sock.recvfrom(1024)
                        open_ports.append(port)
                        print(f"[+] {target}:{port}/UDP - OPEN")
                    except:
                        pass
                    sock.close()
            except Exception as e:
                pass
        
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for t in threads:
            t.join()
        
        self.results['open_ports'][target] = open_ports
        return open_ports
    
    def service_detection(self, target, port):
        """Attempt to detect service running on port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'Server:' in banner:
                    server = banner.split('Server:')[1].split('\r\n')[0].strip()
                    return f"HTTP - {server}"
            
            # For other services, try to grab banner
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Common service identification
            if port == 22 and 'SSH' in banner:
                return f"SSH - {banner}"
            elif port == 21 and 'FTP' in banner:
                return f"FTP - {banner}"
            elif port == 25 and 'SMTP' in banner:
                return f"SMTP - {banner}"
            elif port == 53:
                return "DNS"
            elif port == 3389:
                return "RDP"
            elif banner:
                return banner[:100]
            else:
                return "Unknown service"
                
        except Exception as e:
            return "Service detection failed"
    
    def banner_grab(self, target, ports):
        """Grab banners from open ports"""
        print(f"[+] Starting banner grabbing on {target}")
        services = {}
        
        for port in ports:
            service = self.service_detection(target, port)
            services[port] = service
            print(f"[+] {target}:{port} - {service}")
        
        self.results['services'][target] = services
        return services
    
    def vulnerability_check(self, target, ports):
        """Basic vulnerability checks"""
        print(f"[+] Running basic vulnerability checks on {target}")
        vulns = []
        
        # Check for common vulnerable services
        if 23 in ports:
            vulns.append("Telnet service detected - Unencrypted protocol")
        if 21 in ports:
            vulns.append("FTP service detected - Consider SFTP/FTPS")
        if 139 in ports or 445 in ports:
            vulns.append("SMB service detected - Check for SMB vulnerabilities")
        if 1433 in ports:
            vulns.append("SQL Server detected - Check for SQL injection")
        if 3389 in ports:
            vulns.append("RDP service detected - Ensure strong authentication")
        
        # Check for default ports that might indicate weak security
        web_ports = [80, 8080, 8000, 8888]
        open_web_ports = [p for p in ports if p in web_ports]
        if open_web_ports:
            vulns.append(f"HTTP services on ports {open_web_ports} - Check for HTTPS")
        
        return vulns
    
    def comprehensive_scan(self, target):
        """Perform comprehensive scan on single target"""
        print(f"\n[+] Starting comprehensive scan of {target}")
        print("=" * 50)
        
        # Port scan
        open_ports = self.port_scan(target)
        
        if open_ports:
            # Banner grabbing
            self.banner_grab(target, open_ports)
            
            # Vulnerability checks
            vulns = self.vulnerability_check(target, open_ports)
            if vulns:
                print(f"\n[!] Potential security concerns for {target}:")
                for vuln in vulns:
                    print(f"    - {vuln}")
        else:
            print(f"[-] No open ports found on {target}")
    
    def network_scan(self, network):
        """Perform network-wide scan"""
        print(f"\n[+] Starting network scan of {network}")
        print("=" * 50)
        
        # Discover hosts
        live_hosts = self.ping_sweep(network)
        
        if live_hosts:
            print(f"\n[+] Found {len(live_hosts)} live hosts")
            for host in live_hosts:
                self.comprehensive_scan(host)
        else:
            print("[-] No live hosts discovered")
    
    def save_results(self, filename="scan_results.json"):
        """Save scan results to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n[+] Results saved to {filename}")
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    def generate_report(self):
        """Generate scan report"""
        print("\n" + "=" * 60)
        print("NETWORK SECURITY SCAN REPORT")
        print("=" * 60)
        print(f"Scan Time: {self.results['scan_time']}")
        print(f"Live Hosts: {len(self.results['host_discovery'])}")
        
        total_open_ports = sum(len(ports) for ports in self.results['open_ports'].values())
        print(f"Total Open Ports: {total_open_ports}")
        
        print("\nDETAILED RESULTS:")
        print("-" * 30)
        
        for host in self.results['open_ports']:
            ports = self.results['open_ports'][host]
            if ports:
                print(f"\nHost: {host}")
                print(f"Open Ports: {ports}")
                if host in self.results['services']:
                    print("Services:")
                    for port, service in self.results['services'][host].items():
                        print(f"  {port}: {service}")

def main():
    parser = argparse.ArgumentParser(description="Network Security Probe Tool")
    parser.add_argument('-t', '--target', help='Target IP address')
    parser.add_argument('-n', '--network', help='Network range (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000 or 80,443,22)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--ping-only', action='store_true', help='Only perform ping sweep')
    
    args = parser.parse_args()
    
    # Create probe instance
    probe = NetworkProbe()
    
    print("Network Security Probe Tool")
    print("=" * 60)
    print("WARNING: Only use on networks you own or have permission to test!")
    print("=" * 60)
    
    if args.target:
        if args.ping_only:
            # Just check if host is alive
            result = subprocess.run(['ping', '-c', '1', args.target], 
                                  capture_output=True)
            if result.returncode == 0:
                print(f"[+] {args.target} is alive")
            else:
                print(f"[-] {args.target} is not responding")
        else:
            probe.comprehensive_scan(args.target)
    
    elif args.network:
        if args.ping_only:
            probe.ping_sweep(args.network)
        else:
            probe.network_scan(args.network)
    
    else:
        print("Please specify either -t for single target or -n for network range")
        return
    
    # Generate report
    probe.generate_report()
    
    # Save results if requested
    if args.output:
        probe.save_results(args.output)

if __name__ == "__main__":
    main()

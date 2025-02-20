#!/usr/bin/env python3

import csv
import ipaddress
import time
import logging
import argparse
import concurrent.futures
import json
import platform
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import texttable
import textwrap
from mac_vendor_lookup import MacLookup
import nmap
from scapy.all import ARP, Ether, srp
from tqdm import tqdm
import colorama
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_scan.log'),
        logging.StreamHandler()
    ]
)

class NetworkDevice:
    def __init__(self, ip: str, mac: str):
        self.ip = ip
        self.mac = mac
        self.hostname = "Unknown"
        self.vendor = "Unknown"
        self.os = "Unknown"
        self.open_ports = []
        self.last_seen = datetime.now()
        self.response_time = 0.0
        self.services = {}
        self.is_gateway = False

class EnhancedNetworkScanner:
    def __init__(self, target_network: str, stealth_level: int = 1, ports: List[int] = None):
        self.target_network = target_network
        self.stealth_level = stealth_level
        self.devices: List[NetworkDevice] = []
        self.base_delay = 0.3
        self.ports = ports or [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
        self.mac_lookup = MacLookup()
        self.gateway_ip = self._get_default_gateway()
        
        try:
            self.mac_lookup.update_vendors()
        except Exception as e:
            logging.warning(f"Could not update MAC vendor database: {e}")

        self._print_banner()

    def _print_banner(self):
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════╗
║     Enhanced Network Scanner v2.0          ║
║     Target: {self.target_network:<27} ║
║     Stealth Level: {self.stealth_level}                    ║
╚══════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def _get_default_gateway(self) -> Optional[str]:
        try:
            if platform.system() == "Windows":
                import subprocess
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if "Default Gateway" in line:
                        gateway = line.split(":")[1].strip()
                        if gateway and gateway != "":
                            return gateway
            return None
        except Exception as e:
            logging.warning(f"Could not determine default gateway: {e}")
            return None

    def validate_network(self) -> bool:
        try:
            ipaddress.IPv4Network(self.target_network)
            return True
        except ValueError as e:
            logging.error(f"Invalid network: {self.target_network} - {str(e)}")
            return False

    def adaptive_delay(self) -> float:
        return self.base_delay * (1 + (self.stealth_level - 1) * 0.5)

    def get_service_banner(self, ip: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, port))
                return s.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            return ""

    def scan_device(self, device: NetworkDevice):
        nm = nmap.PortScanner()
        try:
            # OS Detection
            nm.scan(device.ip, arguments='-O --osscan-guess')
            if 'osmatch' in nm[device.ip]:
                device.os = nm[device.ip]['osmatch'][0]['name']

            # Port Scanning
            for port in self.ports:
                try:
                    start_time = time.time()
                    result = nm.scan(device.ip, str(port))
                    scan_time = time.time() - start_time
                    
                    if result['scan'][device.ip]['tcp'][port]['state'] == 'open':
                        service = result['scan'][device.ip]['tcp'][port]['name']
                        banner = self.get_service_banner(device.ip, port)
                        device.open_ports.append({
                            'port': port,
                            'service': service,
                            'banner': banner,
                            'response_time': scan_time
                        })
                    time.sleep(self.adaptive_delay())
                except Exception as e:
                    logging.debug(f"Port {port} scan failed for {device.ip}: {e}")

        except Exception as e:
            logging.warning(f"Device scan failed for {device.ip}: {e}")

    def scan(self):
        logging.info(f"Starting network scan of {self.target_network}")
        print(f"\n{Fore.GREEN}Phase 1: {Style.RESET_ALL}Discovering active devices...")

        arp_request = ARP(pdst=self.target_network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        start_time = time.time()
        answered, _ = srp(arp_request_broadcast, timeout=2, verbose=0)
        
        with tqdm(total=len(answered), desc="Scanning devices", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} devices") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_device = {}
                
                for sent, received in answered:
                    device = NetworkDevice(received.psrc, received.hwsrc)
                    
                    # Check if it's the gateway
                    if device.ip == self.gateway_ip:
                        device.is_gateway = True
                    
                    try:
                        device.hostname = socket.gethostbyaddr(device.ip)[0]
                    except socket.herror:
                        pass

                    try:
                        device.vendor = self.mac_lookup.lookup(device.mac)
                    except Exception:
                        pass

                    self.devices.append(device)
                    future = executor.submit(self.scan_device, device)
                    future_to_device[future] = device
                    
                for future in concurrent.futures.as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        future.result()
                        pbar.update(1)
                    except Exception as e:
                        logging.error(f"Scan failed for {device.ip}: {e}")

        scan_time = time.time() - start_time
        self._print_scan_summary(scan_time)

    def _print_scan_summary(self, scan_time: float):
        table = texttable.Texttable(max_width=100)
        table.set_deco(texttable.Texttable.HEADER | texttable.Texttable.VLINES)
        
        headers = ["IP Address", "Hostname", "MAC Address", "Vendor", "OS", "Open Ports"]
        table.header(headers)
        
        for device in sorted(self.devices, key=lambda x: ipaddress.IPv4Address(x.ip)):
            ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in device.open_ports[:3]])
            if len(device.open_ports) > 3:
                ports_str += f" (+{len(device.open_ports)-3} more)"
                
            row = [
                f"{Fore.GREEN if device.is_gateway else ''}{device.ip}{Style.RESET_ALL}",
                device.hostname[:20] + "..." if len(device.hostname) > 20 else device.hostname,
                device.mac,
                device.vendor[:20] + "..." if len(device.vendor) > 20 else device.vendor,
                device.os[:20] + "..." if len(device.os) > 20 else device.os,
                ports_str
            ]
            table.add_row(row)

        print(f"\n{Fore.CYAN}Scan Results:{Style.RESET_ALL}")
        print(table.draw())
        print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"✓ Total devices found: {len(self.devices)}")
        print(f"✓ Scan duration: {scan_time:.2f} seconds")
        print(f"✓ Gateway IP: {self.gateway_ip or 'Not detected'}")

    def save_results(self, format: str = "csv"):
        if not self.devices:
            logging.warning("No devices found. Nothing to save.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format.lower() == "csv":
            filename = f"scan_results_{timestamp}.csv"
            with open(filename, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=[
                    "IP Address", "MAC Address", "Hostname", "Vendor", "OS", 
                    "Open Ports", "Is Gateway", "Last Seen"
                ])
                writer.writeheader()
                for device in self.devices:
                    writer.writerow({
                        "IP Address": device.ip,
                        "MAC Address": device.mac,
                        "Hostname": device.hostname,
                        "Vendor": device.vendor,
                        "OS": device.os,
                        "Open Ports": ', '.join([f"{p['port']}/{p['service']}" for p in device.open_ports]),
                        "Is Gateway": device.is_gateway,
                        "Last Seen": device.last_seen.isoformat()
                    })
        else:  # JSON format
            filename = f"scan_results_{timestamp}.json"
            with open(filename, 'w', encoding='utf-8') as file:
                json.dump([{
                    "ip": d.ip,
                    "mac": d.mac,
                    "hostname": d.hostname,
                    "vendor": d.vendor,
                    "os": d.os,
                    "open_ports": d.open_ports,
                    "is_gateway": d.is_gateway,
                    "last_seen": d.last_seen.isoformat()
                } for d in self.devices], file, indent=2)

        print(f"\n{Fore.GREEN}Results saved to: {filename}{Style.RESET_ALL}")

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Enhanced Network Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
            Examples:
              %(prog)s 192.168.1.0/24
              %(prog)s 192.168.1.0/24 -s 2 -p 80 443 8080 -f json
              %(prog)s 10.0.0.0/24 --stealth 1 --format csv
        ''')
    )
    parser.add_argument('network', help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('-s', '--stealth', type=int, choices=[1, 2, 3], default=1,
                      help='Stealth level (1=normal, 2=stealthier, 3=stealthiest)')
    parser.add_argument('-p', '--ports', type=int, nargs='+',
                      help='Specific ports to scan (default: common ports)')
    parser.add_argument('-f', '--format', choices=['csv', 'json'], default='csv',
                      help='Output format for results (default: csv)')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    try:
        scanner = EnhancedNetworkScanner(
            target_network=args.network,
            stealth_level=args.stealth,
            ports=args.ports
        )

        if scanner.validate_network():
            scanner.scan()
            scanner.save_results(format=args.format)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

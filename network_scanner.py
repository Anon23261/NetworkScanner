import csv
import ipaddress
import time
from scapy.all import ARP, Ether, srp
import socket

class LivingNetworkScanner:
    def __init__(self, target_network, stealth_level=1):
        self.target_network = target_network
        self.stealth_level = stealth_level
        self.devices = []
        self.base_delay = 0.3 # base delay for adaptive timing

    def validate_network(self):
        try:
            ipaddress.IPv4Network(self.target_network)
            return True
        except ValueError:
            print(f"Invalid network: {self.target_network}")
            return False
        
    def adaptive_delay(self):
        # Increase delay in stealthier modes
        if self.stealth_level == 1:
            return self.base_delay
        elif self.stealth_level == 2:
            return self.base_delay * 1.5
        elif self.stealth_level == 3:
            return self.base_delay * 2
        else:
            return self.base_delay
        
    def scan(self):
        print(f"Scanning network: {self.target_network} with stealth level {self.stealth_level}...")

        arp_request = ARP(pdst=self.target_network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered, _ = srp(arp_request_broadcast, timeout=2, verbose=0)

        for sent, received in answered:
            # Adaptive delay for stealth
            time.sleep(self.adaptive_delay())

            # Avoid re-scanning the same IP to limit traffic
            if not any(device["ip"] == received.psrc for device in self.devices):
                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except socket.herror:
                    hostname = "Unknown"

                self.devices.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "hostname": hostname
                })

    def display_results(self):
        if self.devices:
            print("\n--- Devices Found ---")
            print(f"{'IP Address':<15} {'MAC Address':<17} {'Hostname':<25}")
            print("-" * 58)
            for device in self.devices: 
                print(f"{device['ip']:<15} {device['mac']:<17} {device['hostname']:<25}")
        else:
            print("No devices found.")

    def save_results_to_file(self, filename="results.csv"):
        if self.devices:
            with open(filename, mode='w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=["IP Address", "MAC Address", "Hostname"])
                writer.writeheader()
                for device in self.devices:
                    writer.writerow({
                        "IP Address": device["ip"],
                        "MAC Address": device["mac"],
                        "Hostname": device["hostname"]
                    })
            print(f"\nResults saved to {filename}")
        else:
            print("\nNo devices found. Nothing to save.")

def main():
    # Set target network
    target_network = "192.168.1.0/24"

    # Choose stealth level: 1 (normal), 2 (stealthier), 3 (stealthiest)
    stealth_level = 2 # Adjust as needed

    scanner = LivingNetworkScanner(target_network, stealth_level)

    if scanner.validate_network():
        start_time = time.time()

        # Perform the scan
        scanner.scan()

        # Display results
        scanner.display_results()

        # Save results to file
        scanner.save_results_to_file("results.csv")

        # Show scan time
        end_time = time.time()
        print(f"\nScan completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()

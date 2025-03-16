#!/usr/bin/env python3

import socket
import ssl
from typing import Dict, List, Optional
import requests
from concurrent.futures import ThreadPoolExecutor
import nmap
from src.scanner_logging import SecurityLogger

class SecurityChecker:
    def __init__(self, logger):
        self.logger = logger
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP",
            8080: "HTTP-Proxy"
        }
        self.findings = []

    def check_device_security(self, device) -> List[Dict]:
        """Perform security checks on a device"""
        security_findings = []
        
        # Check for common security issues
        self._check_open_ports(device, security_findings)
        self._check_service_versions(device, security_findings)
        self._check_ssl_security(device, security_findings)
        self._check_default_credentials(device, security_findings)
        
        return security_findings

    def _check_open_ports(self, device, findings: List[Dict]):
        """Check for potentially risky open ports"""
        risky_ports = {
            21: "FTP (clear text)",
            23: "Telnet (clear text)",
            445: "SMB (potential vulnerabilities)",
            3389: "RDP (remote access)"
        }
        
        for port_info in device.open_ports:
            port = port_info['port']
            if port in risky_ports:
                findings.append({
                    'ip': device.ip,
                    'severity': 'MEDIUM',
                    'finding': f'Potentially risky port {port} ({risky_ports[port]}) is open',
                    'details': f'Service: {port_info["service"]}, Banner: {port_info.get("banner", "N/A")}'
                })
                self.logger.log_security_finding(
                    device.ip, 'MEDIUM',
                    f'Risky port {port} open',
                    f'Service: {port_info["service"]}'
                )

    def _check_service_versions(self, device, findings: List[Dict]):
        """Check for outdated or vulnerable service versions"""
        nm = nmap.PortScanner()
        
        for port_info in device.open_ports:
            try:
                result = nm.scan(device.ip, str(port_info['port']), arguments='-sV')
                if device.ip in result['scan']:
                    service_info = result['scan'][device.ip]['tcp'][port_info['port']]
                    if 'version' in service_info:
                        version = service_info['version']
                        product = service_info['product']
                        
                        # Log service version information
                        self.logger.log_network_event(
                            f"Service version detected - IP: {device.ip}, "
                            f"Port: {port_info['port']}, Service: {product}, Version: {version}"
                        )
                        
                        # Check for known vulnerable versions (example)
                        if product.lower() == 'apache' and version.startswith('2.4.'):
                            findings.append({
                                'ip': device.ip,
                                'severity': 'HIGH',
                                'finding': f'Potentially vulnerable {product} version {version}',
                                'details': 'Consider upgrading to latest version'
                            })
            except Exception as e:
                self.logger.log_error(f"Error checking service version for {device.ip}:{port_info['port']}", e)

    def _check_ssl_security(self, device, findings: List[Dict]):
        """Check SSL/TLS configuration for HTTPS services"""
        for port_info in device.open_ports:
            if port_info['service'] in ['https', 'ssl/http']:
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((device.ip, port_info['port'])) as sock:
                        with context.wrap_socket(sock, server_hostname=device.ip) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Check certificate expiration
                            if not cert:
                                findings.append({
                                    'ip': device.ip,
                                    'severity': 'HIGH',
                                    'finding': f'Invalid SSL certificate on port {port_info["port"]}',
                                    'details': 'No valid certificate found'
                                })
                            
                            # Check SSL/TLS version
                            version = ssock.version()
                            if version in ['TLSv1', 'TLSv1.1']:
                                findings.append({
                                    'ip': device.ip,
                                    'severity': 'MEDIUM',
                                    'finding': f'Outdated TLS version ({version})',
                                    'details': 'Upgrade to TLS 1.2 or higher recommended'
                                })
                except Exception as e:
                    self.logger.log_error(f"Error checking SSL security for {device.ip}:{port_info['port']}", e)

    def _check_default_credentials(self, device, findings: List[Dict]):
        """Check for default credentials on common services"""
        common_credentials = {
            'admin': 'admin',
            'root': 'root',
            'administrator': 'password'
        }
        
        # Only check specific services that commonly have web interfaces
        web_ports = [80, 443, 8080, 8443]
        
        for port_info in device.open_ports:
            if port_info['port'] in web_ports:
                try:
                    url = f"http{'s' if port_info['port'] in [443, 8443] else ''}://{device.ip}:{port_info['port']}"
                    response = requests.get(url, timeout=5)
                    
                    if response.status_code == 401:  # Basic auth required
                        findings.append({
                            'ip': device.ip,
                            'severity': 'INFO',
                            'finding': f'Basic authentication found on port {port_info["port"]}',
                            'details': 'Consider using stronger authentication methods'
                        })
                except Exception as e:
                    self.logger.log_error(f"Error checking credentials for {device.ip}:{port_info['port']}", e)

    def generate_security_report(self) -> str:
        """Generate a comprehensive security report"""
        return self.logger.create_security_report(self.findings)

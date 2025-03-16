#!/usr/bin/env python3

import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

class SecurityLogger:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup loggers
        self.network_logger = self._setup_logger("network", "network_scan.log")
        self.security_logger = self._setup_logger("security", "security_events.log")
        self.error_logger = self._setup_logger("error", "error.log")
        
    def _setup_logger(self, name: str, filename: str) -> logging.Logger:
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(
            self.log_dir / filename,
            encoding='utf-8'
        )
        file_handler.setFormatter(
            logging.Formatter(
                '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        )
        logger.addHandler(file_handler)
        
        # Rotating file handler for backup
        rotating_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f"{filename}.backup",
            maxBytes=10485760,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        rotating_handler.setFormatter(file_handler.formatter)
        logger.addHandler(rotating_handler)
        
        return logger
    
    def log_network_event(self, message: str, level: str = "info"):
        """Log network discovery and scanning events"""
        getattr(self.network_logger, level.lower())(message)
    
    def log_security_event(self, message: str, level: str = "info"):
        """Log security-related events and findings"""
        getattr(self.security_logger, level.lower())(message)
    
    def log_error(self, message: str, error: Optional[Exception] = None):
        """Log error events with optional exception details"""
        if error:
            self.error_logger.error(f"{message}: {str(error)}")
        else:
            self.error_logger.error(message)
    
    def log_device_discovery(self, ip: str, mac: str, hostname: str):
        """Log device discovery events"""
        self.network_logger.info(
            f"Device discovered - IP: {ip}, MAC: {mac}, Hostname: {hostname}"
        )
    
    def log_port_scan(self, ip: str, port: int, service: str, is_open: bool):
        """Log port scanning results"""
        status = "open" if is_open else "closed"
        self.network_logger.info(
            f"Port scan result - IP: {ip}, Port: {port}, Service: {service}, Status: {status}"
        )
    
    def log_security_finding(self, ip: str, severity: str, finding: str, details: str):
        """Log security findings with severity levels"""
        self.security_logger.warning(
            f"Security Finding - IP: {ip}, Severity: {severity}, "
            f"Finding: {finding}, Details: {details}"
        )
    
    def log_scan_summary(self, total_devices: int, scan_duration: float,
                        open_ports: int, security_findings: int):
        """Log scan summary information"""
        summary = (
            f"Scan Summary:\n"
            f"  - Total Devices: {total_devices}\n"
            f"  - Scan Duration: {scan_duration:.2f} seconds\n"
            f"  - Open Ports Found: {open_ports}\n"
            f"  - Security Findings: {security_findings}"
        )
        self.network_logger.info(summary)
        self.security_logger.info(summary)
    
    def create_security_report(self, findings: list) -> str:
        """Generate a detailed security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.log_dir / f"security_report_{timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("Network Security Assessment Report\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if findings:
                f.write("Security Findings:\n")
                f.write("-" * 20 + "\n")
                for finding in findings:
                    f.write(f"\nTarget: {finding['ip']}\n")
                    f.write(f"Severity: {finding['severity']}\n")
                    f.write(f"Finding: {finding['finding']}\n")
                    f.write(f"Details: {finding['details']}\n")
                    f.write("-" * 20 + "\n")
            else:
                f.write("No security findings identified.\n")
        
        return str(report_file)

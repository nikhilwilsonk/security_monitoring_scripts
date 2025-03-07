import argparse
import asyncio
import json
import sys

from database import SecurityDatabase
from network_scan import NetworkScanner
from services.threat_detection import ThreatDetector
from utils import logger

class SecurityMonitorCLI:
    def __init__(self):

        self.parser = argparse.ArgumentParser(
            description='Security Monitoring and Analysis Tool',
        )
        self.parser.add_argument(
            '--scan', 
            type=str, 
            help='Network range to scan (e.g., 192.168.1.0/24)',
        )
        self.parser.add_argument(
            '--log-file', 
            type=str, 
            help='Path to log file for threat analysis',
            default='/var/log/system.log'
        )
        self.parser.add_argument(
            '--threat-level', 
            type=str, 
            choices=['low', 'medium', 'high'], 
            default='medium',
            help='Sensitivity level for threat detection'
        )
        self.parser.add_argument(
            '--output', 
            type=str, 
            help='Output file for scan results',
        )
        
    def run(self):
        args = self.parser.parse_args()
        db = SecurityDatabase()
        try:
            if args.scan:
                scanner = NetworkScanner(args.scan)
                scan_results = scanner.scan_network()
                print(scan_results)
                with open(args.output, 'w') as f:
                    json.dump(scan_results, f, indent=2)
                for result in scan_results:
                    db.log_network_scan(result)
            if args.log_file:
                threat_detector = ThreatDetector(args.log_file, args.threat_level)
                threats = asyncio.run(threat_detector.analyze_logs())
                
                for threat in threats:
                    db.log_security_event(
                        event_type='THREAT_DETECTION',
                        severity=threat['risk_level'],
                        details=threat['details']
                    )
                if threats:
                    print("Detected Threats:")
                    for threat in threats:
                        print(f"- {threat['details']} (Risk: {threat['risk_level']})")
        
            
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            sys.exit(1)

if __name__ == '__main__':
    cli=SecurityMonitorCLI()
    cli.run()
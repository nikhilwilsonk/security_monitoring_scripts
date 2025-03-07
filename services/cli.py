import argparse
import json
import sys

from database import SecurityDatabase
from network_scan import NetworkScanner
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
            
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            sys.exit(1)

if __name__ == '__main__':
    cli=SecurityMonitorCLI()
    cli.run()
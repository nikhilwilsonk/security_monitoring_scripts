from typing import Any, Dict, List
import nmap
from utils import logger

class NetworkScanner:
    def __init__(self, target_network: str):

        self.target_network = target_network
        self.nm = nmap.PortScanner()
    
    def scan_network(self) -> List[Dict[str, Any]]:

        logger.info(f"Starting network scan for {self.target_network}")
        
        scan_results = []
        try:
            self.nm.scan(hosts=self.target_network, arguments='-sn -sV')
            
            for host in self.nm.all_hosts():
                host_info = {
                    'ip': host,
                    'hostname': self.nm[host].hostname() or 'Unknown',
                    'status': self.nm[host]['status']['state'],
                    'open_ports': []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_details = {
                            'port': port,
                            'state': self.nm[host][proto][port]['state'],
                            'service': self.nm[host][proto][port]['name']
                        }
                        host_info['open_ports'].append(port_details)
                
                scan_results.append(host_info)
            
            logger.info(f"Network scan completed. Found {len(scan_results)} hosts.")
            return scan_results
        
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            return []

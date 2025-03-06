import json
from sqlite3 import connect, Connection, Cursor
from typing import List, Dict, Any

class SecurityDatabase:
    def __init__(self, db_path='security_monitor.db'):
        self.db_path = db_path
        self._create_tables()
    
    def _create_tables(self):
        with connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    hostname TEXT,
                    open_ports TEXT,
                    scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
    
    def log_network_scan(self, scan_result: Dict[str, Any]):
        """
        Log network scan results to database
        
        Args:
            scan_result (Dict): Scan result details
        """
        with connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO network_scans (ip_address, hostname, open_ports) VALUES (?, ?, ?)',
                (
                    scan_result.get('ip', 'Unknown'),
                    scan_result.get('hostname', 'Unknown'),
                    json.dumps(scan_result.get('open_ports', []))
                )
            )
            conn.commit()

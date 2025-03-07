import json
from sqlite3 import connect
from typing import Dict, Any

class SecurityDatabase:
    def __init__(self, db_path='security_monitor.db'):
        self.db_path = db_path
        self.create_tables()
    
    def create_tables(self):
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
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT,
                    severity TEXT,
                    details TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
    
    def log_network_scan(self, scan_result: Dict[str, Any]):
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
    def log_security_event(self, event_type: str, severity: str, details: str):
        with connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO security_events (event_type, severity, details) VALUES (?, ?, ?)',
                (event_type, severity, details)
            )
            conn.commit()

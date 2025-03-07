import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SecurityMonitor')

threat_signatures = {
    'low': [
        'login attempt',
        'connection from'
    ],
    'medium': [
        'SQL Injection',
        'Potential Brute Force',
        'Unauthorized Access'
    ],
    'high': [
        'Remote Code Execution',
        'Critical Vulnerability',
        'Potential Data Breach'
    ]
}
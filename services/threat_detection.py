from typing import Dict, List
from utils import logger,threat_signatures
import aiofiles

class ThreatDetector:
    def __init__(self, log_file_path: str, threat_level: str = 'medium'):
        self.log_file_path = log_file_path
        self.threat_level = threat_level
        self.threat_signatures = threat_signatures
    
    async def analyze_logs(self) -> List[Dict[str, str]]:
        
        logger.info(f"Analyzing log file: {self.log_file_path}")
        detected_threats = []
        
        try:
            async with aiofiles.open(self.log_file_path, mode='r') as log_file:
                content = await log_file.read()
                for signature in self.threat_signatures.get(self.threat_level, []):
                    if signature.lower() in content.lower():
                        detected_threats.append({
                            'signature': signature,
                            'risk_level': self.threat_level.capitalize(),
                            'details': f'Potential threat detected: {signature}'
                        })
            print(detected_threats)
            return detected_threats
        
        except FileNotFoundError:
            logger.error(f"Log file not found: {self.log_file_path}")
            return []
        except Exception as e:
            logger.error(f"Log analysis error: {e}")
            return []


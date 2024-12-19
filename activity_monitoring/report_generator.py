# report_generator.py

import json
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, log_data: list):
        self.log_data = log_data  # All session activities logged during user interaction

    def generate_report(self, user_id: str, session_id: str) -> str:
        """Generate a session report based on logged activities."""
        report = {
            "session_id": session_id,
            "user_id": user_id,
            "activities": self.log_data,
            "generated_at": datetime.now().isoformat()
        }
        
        # Save report to a file
        report_filename = f"{user_id}_session_{session_id}_report.json"
        with open(report_filename, 'w') as report_file:
            json.dump(report, report_file, indent=4)
        logger.info(f"Report generated for session {session_id}: {report_filename}")
        
        return report_filename

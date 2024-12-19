# activity_logger.py

import requests
import logging
from typing import Dict
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ActivityLogger:
    def __init__(self, wazuh_api_url: str, wazuh_api_token: str):
        self.wazuh_api_url = wazuh_api_url
        self.wazuh_api_token = wazuh_api_token

    def log_activity(self, user_id: str, resource_id: str, action: str) -> None:
        """Log user activities and send them to Wazuh."""
        log_data = {
            "user_id": user_id,
            "resource_id": resource_id,
            "action": action,
            "timestamp": datetime.now().isoformat()
        }
        self._send_to_wazuh(log_data)

    def _send_to_wazuh(self, log_data: Dict):
        """Send the log entry to Wazuh for real-time monitoring."""
        headers = {"Authorization": f"Bearer {self.wazuh_api_token}"}
        response = requests.post(f"{self.wazuh_api_url}/logs", headers=headers, json=log_data)
        if response.status_code == 200:
            logger.info("Activity sent to Wazuh successfully.")
        else:
            logger.error(f"Failed to send activity log to Wazuh: {response.status_code}")

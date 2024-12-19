# device_health_checker.py

import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DeviceHealthChecker:
    def is_security_patch_up_to_date(self) -> bool:
        """Check if system has the latest security patches."""
        result = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
        if "security" not in result.stdout:
            logger.info("Security patches are up-to-date.")
            return True
        logger.warning("Security patches need to be updated.")
        return False

    def is_antivirus_running(self) -> bool:
        """Check if antivirus software is running."""
        result = subprocess.run(["systemctl", "is-active", "clamav-daemon"], capture_output=True, text=True)
        return result.stdout.strip() == "active"

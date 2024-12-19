# main.py

from core.iam_core import IAMService
from core.mfa_module import MFAService
from core.rbac_module import LeastPrivilegeAccessControl, AccessRequest
from policy_engine.advanced_policy_engine import AdvancedPolicyEngine
from policy_engine.policy_management import AccessPolicy, Permission
from security_checks.device_health_checker import DeviceHealthChecker
from activity_monitoring.activity_logger import ActivityLogger
from activity_monitoring.report_generator import ReportGenerator
from utils.logging_setup import setup_logging
from utils.config import WAZUH_API_URL, WAZUH_API_TOKEN

# Setup centralized logging
setup_logging()

# Initialize core services
iam_service = IAMService(secret_key="super_secret_key")
mfa_service = MFAService(email_config={}, sms_config={})
policy_engine = AdvancedPolicyEngine()
access_control = LeastPrivilegeAccessControl(policy_engine)
device_checker = DeviceHealthChecker()
activity_logger = ActivityLogger(wazuh_api_url=WAZUH_API_URL, wazuh_api_token=WAZUH_API_TOKEN)

# Define some example policies
policy1 = AccessPolicy(
    id="policy_1",
    name="Admin Access Policy",
    roles=["admin"],
    resources=["resource_001", "resource_002"],
    permissions=[Permission.READ, Permission.WRITE, Permission.ADMIN],
    conditions={"location": {"operator": "eq", "value": "office"}},
    priority=1
)

policy2 = AccessPolicy(
    id="policy_2",
    name="User Read-Only Policy",
    roles=["user"],
    resources=["resource_001"],
    permissions=[Permission.READ],
    conditions={"time": {"operator": "time_range", "value": ["09:00", "17:00"]}},
    priority=2
)

# Add policies to the policy engine
policy_engine.add_policy(policy1)
policy_engine.add_policy(policy2)

def main():
    # User login and access check flow
    username = "user1"
    password = "strong_password_123"
    token = iam_service.authenticate(username, password)
    
    if token:
        user_id = iam_service.get_user_by_username(username).user_id
        session_id = "session_123"
        
        if device_checker.is_security_patch_up_to_date() and device_checker.is_antivirus_running():
            resource_id = "resource_001"
            action = "read"
            risk_score = 0.3  # Example risk score
            access_request = AccessRequest(user_id=user_id, resource_id=resource_id, action=action)
            if access_control.check_access(access_request, risk_score):
                activity_logger.log_activity(user_id, resource_id, action)
        
        report_generator = ReportGenerator(activity_logger.activity_log)
        report_file = report_generator.generate_report(user_id, session_id)

if __name__ == "__main__":
    main()


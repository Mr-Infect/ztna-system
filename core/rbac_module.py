# rbac_module.py

from typing import List, Dict
from datetime import datetime
import logging
from dataclasses import dataclass  # Import dataclass here
from policy_engine.advanced_policy_engine import AdvancedPolicyEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define AccessRequest class using dataclass
@dataclass
class AccessRequest:
    user_id: str
    resource_id: str
    action: str
    context: Dict = None
    timestamp: datetime = datetime.now()

class LeastPrivilegeAccessControl:
    def __init__(self, policy_engine: AdvancedPolicyEngine):
        self.policy_engine = policy_engine
        self.audit_log: List[Dict] = []

    def check_access(self, request: AccessRequest, risk_score: float) -> bool:
        """Check access using the advanced policy engine."""
        allowed = self.policy_engine.check_access(request, risk_score)
        self._audit_access(request, allowed)
        return allowed

    def _audit_access(self, request: AccessRequest, allowed: bool) -> None:
        """Record an audit log entry for access decisions."""
        audit_entry = {
            'timestamp': request.timestamp,
            'user_id': request.user_id,
            'resource_id': request.resource_id,
            'action': request.action,
            'allowed': allowed
        }
        self.audit_log.append(audit_entry)
        logger.info(f"Access {'allowed' if allowed else 'denied'}: {audit_entry}")


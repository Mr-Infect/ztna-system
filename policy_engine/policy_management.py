# policy_management.py

from typing import List, Dict, Optional
from dataclasses import dataclass, field
from enum import Enum

class Permission(Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"

@dataclass
class MicroSegment:
    segment_id: str
    name: str
    network_range: str  # IP range or CIDR notation
    resources: List[str]  # List of resource IDs accessible within this segment

@dataclass
class AccessPolicy:
    id: str
    name: str
    roles: List[str]  # Roles that have this policy
    resources: List[str]  # Resources this policy applies to
    permissions: List[Permission]  # Allowed actions (e.g., READ, WRITE)
    conditions: Dict[str, Dict] = field(default_factory=dict)  # Access conditions
    micro_segments: List[MicroSegment] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True


from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityFinding:
    ip_address: str
    attack_type: str
    severity: str
    failed_attempts: int
    max_failures_in_window: int
    window_minutes: int
    targeted_users: list[str]
    first_seen: datetime
    last_seen: datetime
    evidence: list[str]
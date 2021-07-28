from dataclasses import dataclass


@dataclass
class PolicyViolation:
    policy_type: str
    friendly_policy_type: str
    message: str

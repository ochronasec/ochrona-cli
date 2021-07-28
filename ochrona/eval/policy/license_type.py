from typing import Any, Dict, List

from ochrona.const import PYTHON_LICENSE_TYPE_POLICY
from ochrona.model.dependency import Dependency
from ochrona.model.policy_violation import PolicyViolation


def evaluate(dependency_list: List[Dependency], policy: Dict[str, Any]):
    """
    Evaluate python license dependencies
    """
    violations = []
    allowed = [p.strip() for p in policy.get("allow_list", "").split(",") if p] or []
    deny = [p.strip() for p in policy.get("deny_list", "").split(",") if p] or []
    if len(allowed) > 0:
        # Test using allow-list approach
        for dep in dependency_list:
            if dep.license_type not in allowed:
                violations.append(
                    PolicyViolation(
                        policy_type=PYTHON_LICENSE_TYPE_POLICY,
                        friendly_policy_type="Python License Type",
                        message=f"'{dep.license_type}' not in list of allowed licenses. (from {dep.full})",
                    )
                )
    else:
        # Test using deny-list approach
        for d in deny:
            for dep in dependency_list:
                if d == dep.license_type:
                    violations.append(
                        PolicyViolation(
                            policy_type=PYTHON_LICENSE_TYPE_POLICY,
                            friendly_policy_type="Python License Type",
                            message=f"'{d}' is a restricted license type based on policy. (from {dep.full})",
                        )
                    )
    return violations


SCHEMA = {"name": PYTHON_LICENSE_TYPE_POLICY, "fields": ["allow_list", "deny_list"]}

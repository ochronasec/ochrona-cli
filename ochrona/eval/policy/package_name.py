# PENDING-DEPRECATION
# "legacy" policies will be removed in a future release
from ochrona.const import PYTHON_PACKAGE_NAME_POLICY
from ochrona.model.policy_violation import PolicyViolation
from ochrona.utils import parse_version_requirements


def evaluate(dependency_list, policy):
    """
    Evaluates python package name dependencies
    """

    violations = []
    allowed = [p.strip() for p in policy.get("allow_list", "").split(",") if p] or []
    deny = [p.strip() for p in policy.get("deny_list", "").split(",") if p] or []
    simple_required_packages = parse_version_requirements(dependency_list)

    if len(allowed) > 0:
        # Test using allow-list approach
        for pkg in list(simple_required_packages.keys()):
            if pkg not in allowed:
                violations.append(
                    PolicyViolation(
                        policy_type=PYTHON_PACKAGE_NAME_POLICY,
                        friendly_policy_type="Python Package Name",
                        message=f"'{pkg}' not in list of allowed packages. (from {pkg}{simple_required_packages[pkg].get('operator', '')}{simple_required_packages[pkg].get('version', '')})",
                    )
                )
    else:
        # Test using deny-list approach
        for d in deny:
            if d in list(simple_required_packages.keys()):
                violations.append(
                    PolicyViolation(
                        policy_type=PYTHON_PACKAGE_NAME_POLICY,
                        friendly_policy_type="Python Package Name",
                        message=f"'{d}' is a restricted package based on policy. (from {d}{simple_required_packages[d].get('operator', '')}{simple_required_packages[d].get('version', '')})",
                    )
                )
    return violations


SCHEMA = {"name": PYTHON_PACKAGE_NAME_POLICY, "fields": ["allow_list", "deny_list"]}

import ochrona.eval.policy.package_name
import ochrona.eval.policy.license_type

from ochrona.const import PYTHON_LICENSE_TYPE_POLICY
from ochrona.const import PYTHON_PACKAGE_NAME_POLICY


def policy_evaluate(dependencies, policies):
    """
    Evauluates dependencies for policy violations.
    """
    violations = []
    for policy in policies:
        policy_type = policy.get("policy_type")
        if policy_type == PYTHON_PACKAGE_NAME_POLICY:
            violations += package_name.evaluate(
                dependency_list=dependencies.flat_list, policy=policy
            )
        elif policy_type == PYTHON_LICENSE_TYPE_POLICY:
            violations += license_type.evaluate(
                dependency_list=dependencies.dependencies, policy=policy
            )
    return violations


POLICY_SCHEMAS = {
    PYTHON_PACKAGE_NAME_POLICY: package_name.SCHEMA,  # type: ignore
    PYTHON_LICENSE_TYPE_POLICY: license_type.SCHEMA,  # type: ignore
}

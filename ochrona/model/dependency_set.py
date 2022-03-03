import collections
from typing import List

from ochrona.model.confirmed_vulnerability import Vulnerability
from ochrona.model.dependency import Dependency
from ochrona.model.policy_violation import PolicyViolation
from ochrona.model.sast_violation import SASTViolation


class DependencySet:
    """
    A Top level dependencies object for a scan.
    """

    _dependencies: List[Dependency] = []
    _flat_list: List[str] = []
    _confirmed_vulnerabilities: List[Vulnerability] = []
    _policy_violations: List[PolicyViolation] = []
    _sast_violations: List[SASTViolation] = []

    def __init__(self, dependencies=[]):
        self._dependencies = dependencies
        self._flat_list = self._flatten_dependencies(dependencies)

    def _flatten_dependencies(self, dependencies):
        """
        Flattens resolved transitive dependencies into a flat list.
        """
        unique_packages = {}
        for dependency in dependencies:
            if dependency.name not in unique_packages:
                unique_packages[dependency.name] = dependency
            else:
                if dependency.version > unique_packages[dependency.name].version:
                    unique_packages[dependency.name] = dependency
        return list([k.full for k in unique_packages.values()])

    @property
    def dependencies(self):
        return self._dependencies

    @property
    def flat_list(self):
        return self._flat_list

    @property
    def confirmed_vulnerabilities(self):
        return self._confirmed_vulnerabilities

    @confirmed_vulnerabilities.setter
    def confirmed_vulnerabilities(self, confirmed_vulnerabilities: List[Vulnerability]):
        self._confirmed_vulnerabilities = confirmed_vulnerabilities

    @property
    def policy_violations(self):
        return self._policy_violations

    @policy_violations.setter
    def policy_violations(self, policy_violations: List[PolicyViolation] = []):
        self._policy_violations = policy_violations

    @property
    def sast_violations(self):
        return self._sast_violations

    @sast_violations.setter
    def sast_violations(self, sast_violations: List[SASTViolation] = []):
        self._sast_violations = sast_violations

    def to_json(self):
        """
        Dumps object to json.
        """
        return json.dumps(self.__dict__, default=complex_handler)


def complex_handler(obj):
    """
    Handles nested serialization to JSON.
    """
    if hasattr(obj, "to_json"):
        return obj.to_json()
    raise TypeError(
        "Object of type {} with value of {} is not JSON serializable".format(
            type(obj), repr(obj)
        )
    )

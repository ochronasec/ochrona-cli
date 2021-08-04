import datetime
import re
from typing import List

from packaging.specifiers import SpecifierSet, Version

from ochrona.model.confirmed_vulnerability import Vulnerability
from ochrona.utils import parse_version_requirements

VERSION_PATTERN = r"^([a-z_]+)([\<\=|\>\=|\=\=|\=|\<|\>|\!\=]*)([\d\.]*)$"


def evaluate(vulns, required_packages) -> List[Vulnerability]:
    """
    Evalutes the required packages and potentially matching vulnerabilities
    and returns a list of confirmed vulnerabilities (if existing).

    :param vulns: Vulns found that match the required packages.
    :param required_packages: The required dependencies to evaluate against.
    :return: dict
    """
    try:
        results = []
        simple_required_packages = parse_version_requirements(required_packages)
        if simple_required_packages:
            for package_name, package_details in simple_required_packages.items():
                if not any(v.get("name") == package_name for v in vulns):
                    continue
                for vulnerability in [
                    v for v in vulns if v.get("name") == package_name
                ]:
                    # Populate vulnerable version lookups
                    vuln_specifiers = SpecifierSet()
                    exact_vuln_values = set(
                        [
                            v["version_value"]
                            for v in vulnerability["affected_versions"]
                            if v["operator"] == "="
                        ]
                    )
                    for versions in vulnerability["affected_versions"]:
                        if versions["operator"] == "=":
                            vuln_specifiers &= f"=={versions['version_value']}"
                        else:
                            vuln_specifiers &= (
                                f"{versions['operator']}{versions['version_value']}"
                            )
                    # Find latest version and requirement operator
                    dependency_version = package_details.get("version", "")

                    # Evaluate
                    if "-" in [s.version for s in vuln_specifiers]:  # type: ignore
                        if package_details:
                            vulnerability["found_version"] = (
                                package_name
                                + package_details.get("operator", "")
                                + package_details.get("version", "")
                            )
                        else:
                            vulnerability["found_version"] = package_name
                        vulnerability[
                            "reason"
                        ] = f"Flagged as a confirmed vulnerability because {package_name} is a required dependency and it has no known remediated versions."
                        results.append(Vulnerability(**vulnerability))
                    elif (
                        Version(dependency_version) in vuln_specifiers
                        or dependency_version in exact_vuln_values
                    ):
                        vulnerability["found_version"] = (
                            package_name
                            + package_details.get("operator", "")
                            + package_details.get("version", "")
                        )
                        vulnerability[
                            "reason"
                        ] = f"Flagged as a confirmed vulnerability because version was an exact match for dependency: {package_name}"
                        results.append(Vulnerability(**vulnerability))
        return results
    except Exception as ex:
        raise Exception("evauluate exception") from ex

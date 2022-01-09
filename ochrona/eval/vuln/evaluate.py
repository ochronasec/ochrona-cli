from packaging.specifiers import SpecifierSet, Version
from packaging.version import InvalidVersion
from typing import Any, Dict, List, Optional, Tuple, Union

from ochrona.eval.parser import parse
from ochrona.eval.models import TokenInstance, Definition
from ochrona.eval.tokens import Token
from ochrona.model.dependency import Dependency
from ochrona.model.confirmed_vulnerability import Vulnerability
from ochrona.utils import parse_version_requirements

EVAL_DICT: Dict[Any, Any] = {
    True: True,
    False: False,
    Token.AND.name: lambda left, right: left and right,
    Token.OR.name: lambda left, right: left or right,
}


def evaluate(
    vulns: List[Dict[str, Any]], required_packages: List[str]
) -> List[Vulnerability]:
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
                    vulnerable_version_expression = vulnerability.get(
                        "vulnerable_version_expression"
                    )
                    if (
                        vulnerable_version_expression
                        and vulnerable_version_expression != ""
                    ):
                        # Utilize vulnerable_version_expression expression
                        results += _evaluate(vulnerability, package_details)
                    else:
                        # TODO REMOVE
                        # Utilize affected_versions array of version checks
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
                            vulnerability[
                                "vulnerable_version_expression"
                            ] = "version==*"
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
                            vulnerability["vulnerable_version_expression"] = ""
                            results.append(Vulnerability(**vulnerability))
        return results
    except Exception as ex:
        raise Exception("evaluate exception") from ex


def _evaluate(
    vulnerability: Dict[str, Any], package_details: Dict[str, str]
) -> List[Vulnerability]:
    version_expression = vulnerability.get("vulnerable_version_expression", "")
    parsed = parse(version_expression)
    dependency_version = package_details.get("version", "")
    boolean_list, logical_list = _inner_evaluate(parsed, dependency_version)
    if len(logical_list) > 0:
        if all(logical_list) or all(boolean_list):
            vulnerability[
                "reason"
            ] = f"Flagged because {dependency_version} matched version expression: {version_expression}"
            vulnerability["found_version"] = dependency_version
            vulnerability["affected_versions"] = []
            return [Vulnerability(**vulnerability)]
        else:
            return []
    else:
        if all(boolean_list):
            vulnerability[
                "reason"
            ] = f"Flagged because {dependency_version} matched version expression: {version_expression}"
            vulnerability["found_version"] = dependency_version
            vulnerability["affected_versions"] = []
            return [Vulnerability(**vulnerability)]
        else:
            return []


def _inner_evaluate(
    parsed: List[Union[TokenInstance, Definition]], dependency_version: str
) -> Tuple[List[bool], List[Any]]:
    boolean_list = []
    logical_list = []
    it = iter(enumerate(parsed))
    for i, element in it:
        if isinstance(element, TokenInstance):
            # TODO - this recursive logic for processing bracketed compound expressions is ugly and complicated
            if element.id == Token.LBRACKET:
                # find next closing bracket
                for j in range(i, len(parsed)):
                    if (
                        isinstance(parsed[j], TokenInstance)
                        and parsed[j].id == Token.RBRACKET  # type: ignore[union-attr]
                    ):
                        tmp_boolean_list, tmp_logical_list = _inner_evaluate(
                            parsed[i + 1 : j], dependency_version
                        )
                        # Compress the logical list output of the nested result into the boolean list of its parent
                        boolean_list += tmp_logical_list
                        # skip past the already processed block
                        for _ in range(i, j):
                            next(it)
                        break
            else:
                boolean_list.append(EVAL_DICT[element.id])
        elif isinstance(element, Definition):
            evaluated = _evaluate_condition(dependency_version, element)
            boolean_list.append(EVAL_DICT[evaluated])

    for i in range(len(boolean_list)):
        if not isinstance(boolean_list[i], bool) and len(boolean_list) > 2:
            logical_list.append(
                boolean_list[i](boolean_list[i - 1], boolean_list[i + 1])
            )
    return (boolean_list, logical_list)


def _evaluate_condition(
    dependency_value: Optional[str], definition: Definition
) -> bool:
    if dependency_value is None:
        return False
    if definition.operator.id == Token.EQUAL:
        if (
            dependency_value == definition.value.value
            or definition.value.id == Token.ANY
        ):
            return True
    elif definition.operator.id == Token.NEQUAL:
        if dependency_value != definition.value.value:
            return True
    elif definition.operator.id == Token.SMALL:
        if _lt_compare(
            dependency_value,
            definition.value.value,
            definition.field.value,
        ):
            return True
    elif definition.operator.id == Token.SMALLEQ:
        if _lte_compare(
            dependency_value,
            definition.value.value,
            definition.field.value,
        ):
            return True
    elif definition.operator.id == Token.LARGE:
        if _gt_compare(
            dependency_value,
            definition.value.value,
            definition.field.value,
        ):
            return True
    elif definition.operator.id == Token.LARGEEQ:
        if _gte_compare(
            dependency_value,
            definition.value.value,
            definition.field.value,
        ):
            return True
    elif definition.operator.id == Token.IN:
        if dependency_value in [
            val.strip() for val in definition.value.value.split(",")
        ]:
            return True
    elif definition.operator.id == Token.NIN:
        if dependency_value not in [
            val.strip() for val in definition.value.value.split(",")
        ]:
            return True
    return False


def _lt_compare(left: str, right: str, field: str) -> bool:

    if field == "version":
        try:
            return Version(left) < Version(right)
        except InvalidVersion:
            return left < right
    else:
        return float(left) < float(right)


def _lte_compare(left: str, right: str, field: str) -> bool:
    if field == "version":
        try:
            return Version(left) <= Version(right)
        except InvalidVersion:
            return left <= right
    else:
        return float(left) <= float(right)


def _gt_compare(left: str, right: str, field: str) -> bool:
    if field == "version":
        try:
            return Version(left) > Version(right)
        except InvalidVersion:
            return left > right
    else:
        return float(left) > float(right)


def _gte_compare(left: str, right: str, field: str) -> bool:
    if field == "version":
        try:
            return Version(left) >= Version(right)
        except InvalidVersion:
            return left >= right
    else:
        return float(left) >= float(right)

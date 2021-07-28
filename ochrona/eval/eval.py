import json
import re

from ochrona.db import VulnDB
from ochrona.eval.vuln import evaluate
from ochrona.eval.policy import policy_evaluate
from ochrona.log import OchronaLogger
from ochrona.model.dependency_set import DependencySet
from ochrona.model.dependency import Dependency

PEP_SUPPORTED_OPERATORS: str = r"==|>=|<=|!=|~=|<|>"
PEP_SUPPORTED_OPERATORS_CAPTURE: str = r"(==|>=|<=|!=|~=|<|>)"


def resolve(logger: OchronaLogger, dependencies=[], policies=[]) -> DependencySet:
    """
    Resolves a list of dependencies into a PythonDependencies object
    """
    db = VulnDB(logger=logger)
    resp = DependencySet([Dependency(dep) for dep in dependencies])
    vulns = []
    for dep in resp.flat_list:
        vulns += db.lookup_by_name(_safe_query_name(dep))

    if vulns:
        resp.confirmed_vulnerabilities = evaluate(vulns, resp.flat_list)

    if len(policies) > 0:
        resp.policy_violations = policy_evaluate(dependencies=resp, policies=policies)
    return resp


def _safe_query_name(package_name):
    return re.split(PEP_SUPPORTED_OPERATORS, package_name)[0]


def _dedupe_dependencies(flat_list):
    """
    Deduplicates the flat list of dependencies to a true set resolving to what we believe is the actual resolution.
    """
    dependency_dict = collections.OrderedDict()
    for dependency in flat_list:
        simple_name = re.split(PEP_SUPPORTED_OPERATORS, dependency)[0]
        if simple_name not in dependency_dict:
            dependency_dict[simple_name] = [dependency]
        else:
            dependency_dict[simple_name].append(dependency)

    final_list = []
    for package_name, version_list in dependency_dict.items():
        final_list.append(_return_best_fit(package_name, *version_list))
    return final_list


def _return_best_fit(base, *versions):
    """
    Returns the best fit semver.

    Note: entries should be somewhat in order of appearance.
    """
    # if only one entry exists, return that
    if len(versions) == 1:
        return versions[0]
    # filter out entries with no version details
    filtered = list(
        filter(lambda v: v if re.search(PEP_SUPPORTED_OPERATORS, v) else None, versions)
    )
    # if all entries were lacking version details, return the base package name
    if not filtered:
        return base
    filtered_split = list(
        map(lambda v: re.split(PEP_SUPPORTED_OPERATORS_CAPTURE, v), filtered)
    )
    operator_list = list(map(lambda o: o[1], filtered_split))
    if "==" in operator_list:
        # If we need an exact match we should take the highest, not the first
        exact_versions = list(
            sorted(
                [
                    [parse(pkg[2]), i]
                    for i, pkg in enumerate(filtered_split)
                    if pkg[1] == "=="
                ],
                key=lambda x: x[0],
                reverse=True,
            )
        )
        return filtered[exact_versions[0][1]]
    if "<=" in operator_list:
        # If we have a less than situation we need to determine the upper bound
        upper_bound = filtered_split.index("<=")[2]
    # Finally return the highest in the list that does not violate the upper bound
    gt_versions = list(
        sorted(
            [
                [parse(pkg[2]), i]
                for i, pkg in enumerate(filtered_split)
                if pkg[1] == ">="
            ],
            key=lambda x: x[0],
            reverse=True,
        )
    )
    if len(gt_versions) > 0:
        return filtered[gt_versions[0][1]]
    return filtered[0]

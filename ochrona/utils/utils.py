from typing import Dict, List


def parse_version_requirements(packages: str) -> Dict[str, Dict[str, str]]:
    """
    Parses a list of requirements in the format <package_name><PEP_OPERATOR><SEM_VER>
    into a dictionary with the format.

    {
        <package_name>: {
            "operator": <PEP_OPERATOR>,
            "version": <SEM_VER>
        }
    }
    :param packages: List of packages with operators and semver
    :return: dict
    """

    def _parse_by_operator(operator: str, package: str) -> List[str]:
        return package.split(operator)

    parsed_results = {}
    potential_operators = ["!=", "==", ">=", "<=", ">", "<", "="]
    for package in packages:
        found = False
        for oper in potential_operators:
            if oper in package and not found:
                parsed = _parse_by_operator(oper, package)
                parsed_results[parsed[0]] = {"operator": oper, "version": parsed[1]}
                found = True
        if not found:
            parsed_results[package] = {}
    return parsed_results

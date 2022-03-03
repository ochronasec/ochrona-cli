from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

from packaging.specifiers import Version

from ochrona.eval.parser import parse
from ochrona.eval.models import TokenInstance, Definition
from ochrona.eval.tokens import Token
from ochrona.model.dependency import Dependency
from ochrona.model.policy_violation import PolicyViolation


EVAL_DICT: Dict[Any, Any] = {
    True: True,
    False: False,
    Token.AND.name: lambda left, right: left and right,
    Token.OR.name: lambda left, right: left or right,
}


def evaluate(dependency_list: List[Dependency], policy: str) -> List[PolicyViolation]:
    parsed = parse(policy)
    boolean_list, logical_list, possible_violating_packages = _inner_evaluate(
        parsed, dependency_list
    )
    if len(logical_list) > 0:
        if all(logical_list) or all(boolean_list):
            return [
                PolicyViolation(
                    policy_type="custom",
                    friendly_policy_type=f"Definition: {policy}",
                    message=f"Policy violated by {','.join(possible_violating_packages)}",
                )
            ]
        else:
            return []
    else:
        if all(boolean_list):
            return [
                PolicyViolation(
                    policy_type="custom",
                    friendly_policy_type=f"Definition: {policy}",
                    message=f"Policy violated by {','.join(possible_violating_packages)}",
                )
            ]
        else:
            return []


def _inner_evaluate(
    parsed: List[Union[TokenInstance, Definition]], dependency_list: List[Dependency]
) -> Tuple[List[bool], List[Any], List[str]]:
    boolean_list = []
    logical_list = []
    possible_violating_packages = []

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
                        (
                            tmp_boolean_list,
                            tmp_logical_list,
                            tmp_possible_violating_packages,
                        ) = _inner_evaluate(parsed[i + 1 : j], dependency_list)
                        # Compress the logical list output of the nested result into the boolean list of its parent
                        boolean_list += tmp_logical_list
                        possible_violating_packages += tmp_possible_violating_packages
                        # skip past the already processed block
                        for _ in range(i, j):
                            next(it)
                        break
            else:
                boolean_list.append(EVAL_DICT[element.id])
        elif isinstance(element, Definition):
            evaluated = _evaluate_condition(dependency_list, element)
            boolean_list.append(EVAL_DICT[evaluated[0]])
            if evaluated[0]:
                # Record package name/version if True
                possible_violating_packages.append(evaluated[1])
    for i in range(len(boolean_list)):
        if not isinstance(boolean_list[i], bool) and len(boolean_list) > 2:
            logical_list.append(
                boolean_list[i](boolean_list[i - 1], boolean_list[i + 1])
            )
    return (boolean_list, logical_list, possible_violating_packages)


def _evaluate_condition(dependency_list, definition: Definition) -> Tuple[bool, str]:
    for dep in dependency_list:
        dependency_value = dep.__dict__.get(f"_reserved_{definition.field.value}")
        if dependency_value is None:
            continue
        if definition.operator.id == Token.EQUAL:
            if (
                not dependency_value == _calculate_value(definition.value)
                or definition.value.id == Token.ANY
            ):
                return (True, dep.full)
        elif definition.operator.id == Token.NEQUAL:
            if not dependency_value != _calculate_value(definition.value):
                return (True, dep.full)
        elif definition.operator.id == Token.SMALL:
            if not _lt_compare(
                dependency_value,
                _calculate_value(definition.value),
                definition.field.value,
            ):
                return (True, dep.full)
        elif definition.operator.id == Token.SMALLEQ:
            if not _lte_compare(
                dependency_value,
                _calculate_value(definition.value),
                definition.field.value,
            ):
                return (True, dep.full)
        elif definition.operator.id == Token.LARGE:
            if not _gt_compare(
                dependency_value,
                _calculate_value(definition.value),
                definition.field.value,
            ):
                return (True, dep.full)
        elif definition.operator.id == Token.LARGEEQ:
            if not _gte_compare(
                dependency_value,
                _calculate_value(definition.value),
                definition.field.value,
            ):
                return (True, dep.full)
        elif definition.operator.id == Token.IN:
            if dependency_value not in [
                val.strip() for val in definition.value.value.split(",")
            ]:
                return (True, dep.full)
        elif definition.operator.id == Token.NIN:
            if dependency_value in [
                val.strip() for val in definition.value.value.split(",")
            ]:
                return (True, dep.full)
        else:
            continue
    return (False, "")


def _calculate_value(value: TokenInstance):
    if value.id == Token.DAYS:
        days_past = int(value.value.replace("NOW-", ""))
        calculated_date = datetime.now() - timedelta(30)
        return calculated_date.isoformat()
    return value.value


def _lt_compare(left, right, field):
    if field == "latest_version":
        return Version(left) < Version(right)
    elif field == "latest_update":
        return _parse_pypi_timestamp(left) < datetime.fromisoformat(right)
    else:
        return float(left) < float(right)


def _lte_compare(left, right, field):
    if field == "latest_version":
        return Version(left) <= Version(right)
    elif field == "latest_update":
        return _parse_pypi_timestamp(left) <= datetime.fromisoformat(right)
    else:
        return float(left) <= float(right)


def _gt_compare(left, right, field):
    if field == "latest_version":
        return Version(left) > Version(right)
    elif field == "latest_update":
        return _parse_pypi_timestamp(left) > datetime.fromisoformat(right)
    else:
        return float(left) > float(right)


def _gte_compare(left, right, field):
    if field == "latest_version":
        return Version(left) >= Version(right)
    elif field == "latest_update":
        return _parse_pypi_timestamp(left) >= datetime.fromisoformat(right)
    else:
        return float(left) >= float(right)


def _parse_pypi_timestamp(timestamp):
    time_format = "%Y-%m-%dT%H:%M:%S.%fZ" if "." in timestamp else "%Y-%m-%dT%H:%M:%SZ"
    return datetime.strptime(timestamp, time_format)

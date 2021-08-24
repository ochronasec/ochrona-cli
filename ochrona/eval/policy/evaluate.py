from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from packaging.specifiers import Version

from ochrona.eval.policy.parser import parse
from ochrona.eval.policy.models import TokenInstance, Definition
from ochrona.eval.policy.tokens import Token
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
    boolean_list = []
    logical_list = []
    possible_violating_packages: List[str] = []
    for element in parsed:
        if isinstance(element, Definition):
            evaluated = evaluate_condition(dependency_list, element)
            boolean_list.append(EVAL_DICT[evaluated[0]])
            if not evaluated[0]:
                # Record package name/version if False
                possible_violating_packages.append(evaluated[1])
        elif isinstance(element, TokenInstance):
            boolean_list.append(EVAL_DICT[element.id])
    for i in range(len(boolean_list)):
        if not isinstance(boolean_list[i], bool):
            logical_list.append(
                boolean_list[i](boolean_list[i - 1], boolean_list[i + 1])
            )
    if len(logical_list) > 0:
        if all(logical_list) or all(boolean_list):
            return []
        else:
            return [
                PolicyViolation(
                    policy_type="custom",
                    friendly_policy_type=f"Definition: {policy}",
                    message=f"Policiy violated by {','.join(possible_violating_packages)}",
                )
            ]
    else:
        if all(boolean_list):
            return []
        else:
            return [
                PolicyViolation(
                    policy_type="custom",
                    friendly_policy_type=f"Definition: {policy}",
                    message=f"Policiy violated by {','.join(possible_violating_packages)}",
                )
            ]


def evaluate_condition(dependency_list, definition: Definition) -> Tuple[bool, str]:
    for dep in dependency_list:
        dependency_value = dep.__dict__.get(f"_reserved_{definition.field.value}")
        if dependency_value is None:
            continue
        if definition.operator.id == Token.EQUAL:
            if not dependency_value == _calculate_value(definition.value):
                return (False, dep.full)
        elif definition.operator.id == Token.NEQUAL:
            if not dependency_value != _calculate_value(definition.value):
                return (False, dep.full)
        elif definition.operator.id == Token.SMALL:
            if not _lt_compare(
                dependency_value,
                _calculate_value(definition.value),
                definition.field.value,
            ):
                return (False, dep.full)
        elif definition.operator.id == Token.SMALLEQ:
            if not _lte_compare(
                dependency_value,
                _calculate_value(definition.value),
                definition.field.value,
            ):
                return (False, dep.full)
        elif definition.operator.id == Token.LARGE:
            if not _gt_compare(
                dependency_value,
                _calculate_value(definition.value),
                definition.field.value,
            ):
                return (False, dep.full)
        elif definition.operator.id == Token.LARGEEQ:
            if not _gte_compare(
                dependency_value,
                _calculate_value(definition.value),
                definition.field.value,
            ):
                return (False, dep.full)
        if definition.operator.id == Token.IN:
            if dependency_value not in [
                val.strip() for val in definition.value.value.split(",")
            ]:
                return (False, dep.full)
        elif definition.operator.id == Token.NIN:
            if dependency_value in [
                val.strip() for val in definition.value.value.split(",")
            ]:
                return (False, dep.full)
        else:
            continue
    return (True, "")


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

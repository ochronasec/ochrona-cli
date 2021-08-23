from typing import Optional, Tuple

from ochrona.eval.policy.models import Definition, TokenInstance
from ochrona.eval.policy.parser import parse
from ochrona.model.dependency import Dependency


def validate(policy: str) -> Tuple[bool, Optional[str]]:
    try:
        parsed = parse(policy)
        valid_fields = _get_valid_fields()
        if (
            isinstance(parsed, list)
            and all(
                [
                    isinstance(elem, TokenInstance) or isinstance(elem, Definition)
                    for elem in parsed
                ]
            )
            and all(
                [
                    elem.field.value in valid_fields
                    for elem in parsed
                    if isinstance(elem, Definition)
                ]
            )
            and len(parsed) > 0
        ):
            return (True, None)
        return (False, "Policy could not be parsed or contains an invalid field.")
    except Exception:
        return (False, "Policy could not be parsed or contains an invalid field.")


def _get_valid_fields():
    return [
        field.replace("_reserved_", "")
        for field in Dependency.__dict__
        if (field.startswith("_reserved_"))
    ]

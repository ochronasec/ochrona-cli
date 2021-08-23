from typing import List, Optional, Tuple, Union

from ochrona.eval.policy.lexer import lexer
from ochrona.eval.policy.models import Definition, TokenInstance
from ochrona.eval.policy.tokens import Token, CONDITIONAL_OPERATORS, LOGICAL_OPERATORS


def parse(policy: str) -> List[Union[TokenInstance, Definition]]:
    lexed = list(lexer(policy))
    # Remove whitespace
    lexed = [t for t in lexed if t.id != Token.WHITESPACE]
    # Parse
    parsed: List[Union[TokenInstance, Definition]] = []
    for i in range(len(lexed)):
        if lexed[i].id in LOGICAL_OPERATORS:
            parsed.append(lexed[i])
        else:
            if lexed[i].id in CONDITIONAL_OPERATORS:
                parsed.append(Definition(lexed[i - 1], lexed[i], lexed[i + 1]))
    return parsed


def validate(policy: str) -> Tuple[bool, Optional[str]]:
    try:
        parsed = parse(policy)
        if (
            isinstance(parsed, list)
            and all(
                [
                    isinstance(elem, TokenInstance) or isinstance(elem, Definition)
                    for elem in parsed
                ]
            )
            and len(parsed) > 0
        ):
            return (True, None)
        return (False, "Policy could not be parsed.")
    except Exception:
        return (False, "Policy could not be parsed.")

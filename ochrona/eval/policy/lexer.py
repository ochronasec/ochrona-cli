from typing import Generator

from ochrona.eval.policy.models import TokenInstance
from ochrona.eval.policy.tokens import Token


def lexer(data: str) -> Generator[TokenInstance, str, None]:
    pos = 0
    while pos < len(data):
        for tokenId in Token:
            if tokenId.value.match(data, pos):  # type: ignore
                match = tokenId.value.match(data, pos)  # type: ignore
                pos = match.end(0)  # type: ignore
                yield TokenInstance(tokenId.name, match.group(0))  # type: ignore
                break
        else:
            pos += 1
    else:
        yield TokenInstance(Token.WHITESPACE, " ")

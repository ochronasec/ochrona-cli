import re
from enum import Enum


class TokenEnum(Enum):
    def __eq__(self, b) -> bool:
        """When I do == between the Enum I want to check the name"""
        if isinstance(b, str):
            return self.name == b
        else:
            return self.name == b.name

    def __hash__(self):
        return id(self.name)


class Token(TokenEnum):
    # logical operators
    AND = re.compile(r"AND")
    OR = re.compile(r"OR")
    # precedence operators
    LBRACKET = re.compile(r"\(")
    RBRACKET = re.compile(r"\)")
    # conditional operators
    EQUAL = re.compile(r"\=\=")
    NEQUAL = re.compile(r"!\=")
    SMALLEQ = re.compile(r"<\=")
    SMALL = re.compile(r"<")
    LARGEEQ = re.compile(r">\=")
    LARGE = re.compile(r">")
    IN = re.compile(r"IN")
    NIN = re.compile(r"NIN")
    # special values
    DAYS = re.compile(r"NOW-[0-9]")
    # data types
    WHITESPACE = re.compile(r"(\t|\n|\s|\r)+")
    ANY = re.compile(r"\*")
    STRING = re.compile(r"[_a-zA-Z0-9\.\-\,\:]*")


LOGICAL_OPERATORS = [Token.AND, Token.OR]
CONDITIONAL_OPERATORS = [
    Token.EQUAL,
    Token.NEQUAL,
    Token.SMALL,
    Token.SMALLEQ,
    Token.LARGE,
    Token.LARGEEQ,
    Token.IN,
    Token.NIN,
]

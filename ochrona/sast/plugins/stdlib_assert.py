import ast

from ochrona.model.sast_violation import SASTViolation
from ochrona.sast.plugins.base import BaseOchronaPlugin


class StdLibAssert(BaseOchronaPlugin):
    """
    This plugin test checks for the use of Python's assert keyword.
    """

    _id: str = "O003"
    message: str = "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code. See https://cwe.mitre.org/data/definitions/703.html and https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement"

    def visit_Assert(self, node):
        """
        Check instance of ast.Assert
        """
        if isinstance(node, ast.Assert):
            self.violations.append(
                SASTViolation(
                    node=node,
                    message=self.message,
                    location=f"{self.file_path}:{node.lineno}:{node.col_offset}",
                    id=self._id,
                    severity="LOW",
                    confidence="HIGH",
                )
            )

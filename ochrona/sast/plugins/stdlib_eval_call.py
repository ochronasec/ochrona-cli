import ast

from ochrona.model.sast_violation import SASTViolation
from ochrona.sast.plugins.base import BaseOchronaPlugin

EVAL_PATTERN = "eval"


class StdLibEvalCall(BaseOchronaPlugin):
    """
    This plugin test checks for the use of Python's `eval` method or keyword. The
    Python docs succinctly describe why the use of `eval` is risky.
    """

    _id: str = "O002"
    message: str = "Use of `eval` from the Standard Library is discouraged due to RCE risks, see https://docs.python.org/3/library/functions.html#eval"

    def visit_Call(self, node):
        """
        Check for eval within ast.Call
        """
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == EVAL_PATTERN:
                self.violations.append(
                    SASTViolation(
                        node=node,
                        message=self.message,
                        location=f"{self.file_path}:{node.lineno}:{node.col_offset}",
                        id=self._id,
                        severity="MEDIUM",
                        confidence="MEDIUM",
                    )
                )
            else:
                for arg in node.args:
                    if isinstance(arg, ast.Call):
                        self.visit_Call(arg)

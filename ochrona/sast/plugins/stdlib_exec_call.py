import ast

from ochrona.model.sast_violation import SASTViolation
from ochrona.sast.plugins.base import BaseOchronaPlugin

EXEC_PATTERN = "exec"


class StdLibExecCall(BaseOchronaPlugin):
    """
    This plugin test checks for the use of Python's `exec` method or keyword. The
    Python docs succinctly describe why the use of `exec` is risky.
    """

    _id: str = "O001"
    message: str = "Use of `exec` from the Standard Library is discouraged due to RCE risks, see https://docs.python.org/3/library/functions.html#exec"

    def visit_Call(self, node):
        """
        Check for exec within ast.Call
        """
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == EXEC_PATTERN:
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

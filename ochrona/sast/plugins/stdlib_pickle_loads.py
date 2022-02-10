import ast

from ochrona.model.sast_violation import SASTViolation
from ochrona.sast.plugins.base import BaseOchronaPlugin

METHOD_PATTERN = "loads"
PACKAGE_PATTERN = "pickle"


class StdLibPickleLoads(BaseOchronaPlugin):
    """
    This plugin test checks for the use of the unsafe pickle.loads method.
    """

    _id: str = "O005"
    message: str = "pickle.loads from the Standard Library is an unsafe method because arbitrary code can be defined within the __reduce__ method of the pickled object. See https://docs.python.org/3/library/pickle.html"

    def visit_Call(self, node):
        """
        Check for pickle.load within ast.Call
        """
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                # direct import
                if node.func.attr == METHOD_PATTERN and PACKAGE_PATTERN in self.imports:
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
            elif isinstance(node.func, ast.Name):
                # partial import
                if node.func.id == METHOD_PATTERN and PACKAGE_PATTERN in self.imports:
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

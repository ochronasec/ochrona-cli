import ast

from ochrona.model.sast_violation import SASTViolation
from ochrona.sast.plugins.base import BaseOchronaPlugin

METHOD_PATTERN = "extractall"
PACKAGE_PATTERN = "tarfile"


class StdLibTarfileExtractall(BaseOchronaPlugin):
    """
    This plugin test checks for the use of Python's tarfile.extractall method.
    """

    _id: str = "O004"
    message: str = "Use of `tarfile.extractall` from the Standard Library is discouraged without additional checks to prevent arbitrary file write. Tarsafe (https://pypi.org/project/tarsafe/) can be used as a safer drop-in replacement."

    def visit_Call(self, node):
        """
        Check for tarfile.extractall within ast.Call
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

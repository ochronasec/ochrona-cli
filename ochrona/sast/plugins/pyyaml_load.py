import ast

from ochrona.model.sast_violation import SASTViolation
from ochrona.sast.plugins.base import BaseOchronaPlugin

METHOD_PATTERN = "load"
PACKAGE_PATTERN = "yaml"
SAFE_ARGS = ["SafeLoader", "CSafeLoader"]


class PyyamlLoad(BaseOchronaPlugin):
    """
    This plugin test checks for the use of PyYaml's load method.
    """

    _id: str = "O101"
    message: str = "The `load` method from PyYaml allows for arbitrary object creation, `safe_yaml` should be considered instead. See https://pyyaml.org/wiki/PyYAMLDocumentation#LoadingYAML."

    def visit_Call(self, node):
        """
        Check for pyyaml.load within ast.Call
        """
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                # direct import
                if node.func.attr == METHOD_PATTERN and PACKAGE_PATTERN in self.imports:
                    args = self._args_to_dict(node)
                    if args.get("Loader") not in SAFE_ARGS:
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
                    args = self._args_to_dict(node)
                    if args.get("Loader") not in SAFE_ARGS:
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

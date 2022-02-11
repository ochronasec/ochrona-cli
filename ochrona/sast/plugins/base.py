import ast
from typing import Any, Dict, List, Optional, Set

from ochrona.model.sast_violation import SASTViolation


class BaseOchronaPlugin(ast.NodeVisitor):
    """
    Defines a single SAST check.
    """

    def __init__(self, file_path):
        self.file_path = file_path
        self.imports: Set[str] = set()
        self.violations: List[SASTViolation] = []

    def visit_Import(self, node):
        """
        Records imported modules
        """
        for nodename in node.names:
            if nodename.name:
                self.imports.add(nodename.name)
            if nodename.asname:
                self.imports.add(nodename.asname)

    def visit_ImportFrom(self, node):
        self.imports.add(node.module)

    def _args_to_dict(self, node: ast.Call) -> Dict[Optional[str], Any]:
        args = {}
        for arg in node.keywords:
            if isinstance(arg.value, ast.Attribute):
                args[arg.arg] = arg.value.attr
            elif isinstance(arg.value, ast.NameConstant):
                args[arg.arg] = arg.value.value
        return args

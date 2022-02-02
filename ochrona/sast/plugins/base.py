import ast
from typing import List

from ochrona.model.sast_violation import SASTViolation


class BaseOchronaPlugin(ast.NodeVisitor):
    """
    Defines a single SAST check.
    """

    def __init__(self, file_path):
        self.file_path = file_path
        self.violations: List[SASTViolation] = []

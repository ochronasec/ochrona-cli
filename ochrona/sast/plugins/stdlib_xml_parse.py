import ast

from ochrona.model.sast_violation import SASTViolation
from ochrona.sast.plugins.base import BaseOchronaPlugin

METHOD_PATTERN = "parse"
PACKAGE_PATTERN_SET = {"xml", "xml.etree", "xml.etree.ElementTree"}


class StdLibXMLParse(BaseOchronaPlugin):
    """
    This plugin test checks for the use of Python's xml.etree.ElementTree.parse method.
    """

    _id: str = "O006"
    message: str = "The xml processing module from the Python Standard Library is not secure against maliciously crafted documents. See https://docs.python.org/3/library/xml.html#xml-vulnerabilities. Consider https://pypi.org/project/defusedxml/ as a direct replacement."

    def visit_Call(self, node):
        """
        Check for xml.etree.ElementTree.parse within ast.Call
        """
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                # direct import
                if (
                    node.func.attr == METHOD_PATTERN
                    and PACKAGE_PATTERN_SET & self.imports
                ):
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
                if (
                    node.func.id == METHOD_PATTERN
                    and PACKAGE_PATTERN_SET & self.imports
                ):
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

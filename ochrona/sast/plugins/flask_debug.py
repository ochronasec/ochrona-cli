import ast

from ochrona.model.sast_violation import SASTViolation
from ochrona.sast.plugins.base import BaseOchronaPlugin

METHOD_PATTERN = "run"
PACKAGE_PATTERN = "flask"


class FlaskRunDebug(BaseOchronaPlugin):
    """
    This plugin test checks debug=True in Flask app.run
    """

    _id: str = "O103"
    message: str = "Flask in debug mode allows for arbitrary code execution via access to the Werkzeug debugger. See https://flask.palletsprojects.com/en/2.0.x/quickstart/#debug-mode and https://werkzeug.palletsprojects.com/en/0.14.x/debug/#debugger-pin."

    def visit_Call(self, node):
        """
        Check for debug=True
        """
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                # direct import
                if node.func.attr == METHOD_PATTERN and PACKAGE_PATTERN in self.imports:
                    args = self._args_to_dict(node)
                    if args.get("debug") is True:
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
                    if args.get("debug") is True:
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

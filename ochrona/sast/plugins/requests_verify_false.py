import ast

from ochrona.model.sast_violation import SASTViolation
from ochrona.sast.plugins.base import BaseOchronaPlugin

METHOD_PATTERN_SET = {"get", "options", "head", "post", "put", "patch", "delete"}
PACKAGE_PATTERN = "requests"


class RequestsVerifyFalse(BaseOchronaPlugin):
    """
    This plugin test checks for insecure usage of the requests library.
    """

    _id: str = "O102"
    message: str = "Verification disabled for Request's methods will cause the client to implicitly trust any certificate. See https://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification."

    def visit_Call(self, node):
        """
        Check for verify=False within requests
        """
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                # direct import
                if (
                    node.func.attr in METHOD_PATTERN_SET
                    and PACKAGE_PATTERN in self.imports
                ):
                    args = self._args_to_dict(node)
                    if args.get("verify") == False:
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
                    node.func.id in METHOD_PATTERN_SET
                    and PACKAGE_PATTERN in self.imports
                ):
                    args = self._args_to_dict(node)
                    if args.get("verify") == False:
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

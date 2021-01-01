import ast

from typing import List

from ochrona.exceptions import OchronaFileException


class SetupFile:
    @staticmethod
    def parse(file_path: str, include_dev: bool = False) -> List[str]:
        """
        Parses a setup.py into a list of requirements.

        :param file_path: setup.py path
        :return: list<str> list of dependencies ['dependency==semvar']
        """
        setup_func_names = {"setup", "setuptools.setup"}
        try:
            dependencies = []
            with open(file_path) as setuppy:
                tree = ast.parse(setuppy.read())
                for body in tree.body:
                    if isinstance(body, ast.Expr):
                        if body.value.func.id in setup_func_names:  # type: ignore[attr-defined]
                            for kw in body.value.keywords:  # type: ignore[attr-defined]
                                if kw.arg == "install_requires":
                                    dependencies += [arg.s for arg in kw.value.elts]
                                elif kw.arg == "tests_require" and include_dev:
                                    dependencies += [arg.s for arg in kw.value.elts]
            return dependencies
        except OSError as ex:
            raise OchronaFileException(f"OS error when parsing {file_path}") from ex
        except AttributeError as ex:
            raise OchronaFileException(f"AST error when parsing {file_path}") from ex

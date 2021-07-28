from typing import List

from ochrona.const import INVALID_REQUIREMENTS_LINES
from ochrona.exceptions import OchronaFileException


class RequirementsFile:
    @staticmethod
    def parse(file_path: str) -> List[str]:
        """
        Parses a requirements.txt style file into a list of requirements.

        :param file_path: requirements*.txt file path.
        :return: list<str> list of dependencies ['dependency==semvar']
        """
        try:
            with open(file_path) as rfile:
                deps = [line.rstrip("\n") for line in rfile]
                return [
                    RequirementsFile.clean_dependency(dep)
                    for dep in deps
                    if not any(
                        [dep.strip().startswith(s) for s in INVALID_REQUIREMENTS_LINES]
                    )
                ]
        except OSError as ex:
            raise OchronaFileException(f"OS error when parsing {file_path}") from ex

    @staticmethod
    def direct_parse(direct: str) -> List[str]:
        """
        Parses a requirements.txt style string into a list of requirements.

        :param file_path: requirements*.txt file path.
        :return: list<str> list of dependencies ['dependency==semvar']
        """
        try:
            deps = direct.split("\n")
            return [
                RequirementsFile.clean_dependency(dep)
                for dep in deps
                if not any(
                    [dep.strip().startswith(s) for s in INVALID_REQUIREMENTS_LINES]
                )
            ]
        except OSError as ex:
            raise OchronaFileException(f"OS error when parsing {direct}") from ex

    @staticmethod
    def clean_dependency(dependency: str) -> str:
        """
        Removes any comments or hashes following the dependency.

        :param file_path: a dependency with optional pinned version
        :return: str a cleaned dependency string
        """
        if " " in dependency or ";" in dependency or "#" in dependency:
            return dependency.split(" ")[0].replace(";", "")
        return dependency

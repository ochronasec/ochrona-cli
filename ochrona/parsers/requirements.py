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
                    dep
                    for dep in deps
                    if not any([dep.startswith(s) for s in INVALID_REQUIREMENTS_LINES])
                ]
        except OSError as ex:
            raise OchronaFileException(f"OS error when parsing {file_path}") from ex

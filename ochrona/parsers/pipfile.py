import json
from typing import List

from ochrona.exceptions import OchronaFileException


class Pipfile:
    @staticmethod
    def parse(file_path: str, include_dev: bool = False) -> List[str]:
        """
        Parses a Pipfile.lock into a list of requirements.

        :param file_path: Pipfile.lock path
        :return: list<str> list of dependencies ['dependency==semvar']
        """
        try:
            dependencies = []
            with open(file_path) as pipfile:
                data = json.load(pipfile)
                if "default" in data:
                    for name, value in data["default"].items():
                        dependencies.append(f"{name}{value['version']}")
                if "develop" in data and include_dev:
                    for name, value in data["develop"].items():
                        dependencies.append(f"{name}{value['version']}")
            return dependencies
        except OSError as ex:
            raise OchronaFileException(f"OS error when parsing {file_path}") from ex

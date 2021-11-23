import json
from typing import Dict, List, Union, Sequence

from ochrona.exceptions import OchronaFileException


class Pipfile:
    @staticmethod
    def parse(
        file_path: str, include_dev: bool = False
    ) -> List[Dict[str, Union[str, Sequence[str]]]]:
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
                        dependency = {
                            "version": f"{name}{value['version']}",
                            "hashes": [h for h in value["hashes"]],
                        }
                        dependencies.append(dependency)
                if "develop" in data and include_dev:
                    for name, value in data["develop"].items():
                        dependency = {
                            "version": f"{name}{value['version']}",
                            "hashes": [h for h in value["hashes"]],
                        }
                        dependencies.append(dependency)
            return dependencies
        except OSError as ex:
            raise OchronaFileException(f"OS error when parsing {file_path}") from ex

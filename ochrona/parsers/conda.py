import yaml
from typing import List

from ochrona.exceptions import OchronaFileException


class CondaFile:
    @staticmethod
    def parse(file_path: str) -> List[str]:
        """
        Parses a conda.yml into a list of requirements.
        NOTE: This currently only returns pip-based dependencies.

        :param file_path: conda.yml path
        :return: list<str> list of dependencies ['dependency==semvar']
        """
        try:
            dependencies = []
            with open(file_path) as conda_file:
                data = yaml.safe_load(conda_file)
                if (
                    data
                    and isinstance(data, dict)
                    and "dependencies" in data
                    and isinstance(data.get("dependencies"), list)
                ):
                    for line in data.get("dependencies", []):
                        if isinstance(line, dict) and "pip" in line:
                            for _, req in enumerate(line.get("pip", {})):
                                dependencies.append(req)
                        else:
                            # Non-pip specified dependencies
                            continue
            return dependencies
        except yaml.YAMLError as ex:
            raise OchronaFileException(f"Yaml error when parsion {file_path}") from ex
        except OSError as ex:
            raise OchronaFileException(f"OS error when parsing {file_path}") from ex

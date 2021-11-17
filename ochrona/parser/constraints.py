from typing import Dict, List, Union

from ochrona.exceptions import OchronaFileException


class ConstraintsFile:
    @staticmethod
    def parse(file_path: str) -> List[Dict[str, Union[str, List[str]]]]:
        """
        Parses a constraints.txt style file into a list of requirements.

        :param file_path: constraints*.txt file path.
        :return: list<str> list of dependencies ['dependency==semvar']
        """
        try:
            with open(file_path) as rfile:
                return [{"version": line.rstrip("\n"), "hashes": []} for line in rfile]
        except OSError as ex:
            raise OchronaFileException(f"OS error when parsing {file_path}") from ex

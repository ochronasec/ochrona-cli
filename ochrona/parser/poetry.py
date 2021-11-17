from typing import Dict, List, Sequence

import toml
from ochrona.exceptions import OchronaFileException


class PoetryFile:
    @staticmethod
    def parse(
        file_path: str, include_dev: bool = False
    ) -> List[Dict[str, Sequence[str]]]:
        """
        Parses a poetry.lock file into a list of requirements.

        :param file_path: poetry.lock file path
        :return: list<str> list of dependencies ['dependency==semvar']
        """
        dependencies = []
        try:
            with open(file_path) as poetry_lock:
                parsed = toml.load(poetry_lock)
                for pkg in parsed.get("package", []):
                    if pkg.get("category") == "main":
                        dependencies.append(
                            {
                                "version": f"{pkg.get('name')}=={pkg.get('version')}",
                                "hashes": [],
                            }
                        )
                    elif pkg.get("category") == "dev" and include_dev:
                        dependencies.append(
                            {
                                "version": f"{pkg.get('name')}=={pkg.get('version')}",
                                "hashes": [],
                            }
                        )
            return dependencies
        except OSError as ex:
            raise OchronaFileException(f"OS error when parsing {file_path}") from ex
        except toml.decoder.TomlDecodeError as ex:  # type: ignore[attr-defined]
            raise OchronaFileException(
                f"Could not parse {file_path} - is TOML valid?"
            ) from ex

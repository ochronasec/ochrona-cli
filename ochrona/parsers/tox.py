from configparser import ConfigParser, NoOptionError
from io import StringIO
from typing import List

from ochrona.const import TOX_LINKED_REQUIREMENTS, INVALID_TOX_LINES, TOX_INI
from ochrona.parsers.requirements import RequirementsFile


class ToxFile:
    @staticmethod
    def parse(file_path: str) -> List[str]:
        """
        Parses a tox.ini into a list of requirements.

        :param file_path: tox.ini path
        :return: list<str> list of dependencies ['dependency==semvar']
        """
        dependencies = []
        with open(file_path) as tox:
            parser = ConfigParser()
            parser.read_file(tox)
            for section in parser.sections():
                try:
                    deps = parser.get(section=section, option="deps")
                    for _, line in enumerate(deps.splitlines()):
                        if line.startswith(TOX_LINKED_REQUIREMENTS):
                            path = ToxFile._tox_path(file_path)
                            req_file_name = line.replace(TOX_LINKED_REQUIREMENTS, "")
                            return RequirementsFile.parse(f"{path}{req_file_name}")
                        elif not any([line.startswith(i) for i in INVALID_TOX_LINES]):
                            if ":" in line:
                                # requirement is specified with an environment
                                dependencies.append(line.split(":")[-1].strip())
                            else:
                                if line != "":
                                    # plain requirement
                                    dependencies.append(line)
                        else:
                            pass  # did not find valid line to parse
                except NoOptionError:
                    pass
        return dependencies

    @staticmethod
    def _tox_path(tox_file_path):
        return tox_file_path.replace(TOX_INI, "")

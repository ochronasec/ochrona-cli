from ochrona.parser.conda import CondaFile
from ochrona.parser.constraints import ConstraintsFile
from ochrona.parser.pipfile import Pipfile
from ochrona.parser.poetry import PoetryFile
from ochrona.parser.requirements import RequirementsFile
from ochrona.parser.setup_ import SetupFile
from ochrona.parser.tox import ToxFile


class Parsers:
    @property
    def conda(self):
        return CondaFile

    @property
    def constraints(self):
        return ConstraintsFile

    @property
    def pipfile(self):
        return Pipfile

    @property
    def poetry(self):
        return PoetryFile

    @property
    def requirements(self):
        return RequirementsFile

    @property
    def setup(self):
        return SetupFile

    @property
    def tox(self):
        return ToxFile

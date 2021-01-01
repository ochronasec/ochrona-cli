from ochrona.parsers.conda import CondaFile
from ochrona.parsers.constraints import ConstraintsFile
from ochrona.parsers.pipfile import Pipfile
from ochrona.parsers.poetry import PoetryFile
from ochrona.parsers.requirements import RequirementsFile
from ochrona.parsers.setup_ import SetupFile
from ochrona.parsers.tox import ToxFile


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

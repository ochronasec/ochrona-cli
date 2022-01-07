import os

from rich import print

from ochrona.config import OchronaConfig
from ochrona.model.dependency_set import DependencySet


class BaseReport:
    INFO = "[blue]"
    ENDC = "[/]"
    NO = "default"

    @staticmethod
    def print_report_number(index: int, total: int, color: bool = True):
        print(
            f"{os.linesep}{BaseReport.INFO if color else BaseReport.NO}Report {index + 1} of {total}{BaseReport.ENDC if color else BaseReport.NO}"
        )

    @staticmethod
    def print_report_source(source: str, color: bool = True):
        if color:
            print(f"[bold white italics]File: {source}[/]")
        else:
            print(f"Analysis: {source}")

    @staticmethod
    def generate(
        result: DependencySet,
        config: OchronaConfig,
        source: str,
        total: int,
        index: int,
    ):
        return NotImplemented

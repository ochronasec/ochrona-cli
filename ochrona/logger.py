# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""
import platform
from ochrona import __version__


class OchronaLogger:
    HEADER = """{color}
,---.     |                        
|   |,---.|---.,---.,---.,---.,---.
|   ||    |   ||    |   ||   |,---|
`---'`---'`   '`    `---'`   '`---^
                            v. {version} {endc}
                            https://ochrona.dev   
                            """

    INFO = "\033[94m"
    PASS = "\033[92m"
    WARNING = "\033[93m"
    ERROR = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    NO = ""

    def __init__(self, config):
        self._debug = config.debug
        self._silent = config.silent
        self._color = config.color_output

    def debug(self, val):
        if self._debug and not self._silent:
            print(
                f"{OchronaLogger.INFO if self._color else OchronaLogger.NO}[DEBUG] {val}{OchronaLogger.ENDC if self._color else OchronaLogger.NO}"
            )

    def info(self, val):
        if not self._silent:
            print(
                f"{OchronaLogger.INFO if self._color else OchronaLogger.NO}{val}{OchronaLogger.ENDC if self._color else OchronaLogger.NO}"
            )

    def warn(self, val):
        if not self._silent:
            print(
                f"{OchronaLogger.WARNING if self._color else OchronaLogger.NO}[!] {val}{OchronaLogger.ENDC if self._color else OchronaLogger.NO}"
            )

    def error(self, val):
        if not self._silent:
            print(
                f"{OchronaLogger.ERROR if self._color else OchronaLogger.NO}[!] {val}{OchronaLogger.ENDC if self._color else OchronaLogger.NO}"
            )

    @staticmethod
    def static_error(val):
        color = (
            OchronaLogger.ERROR if platform.system() != "Windows" else OchronaLogger.NO
        )
        endc = (
            OchronaLogger.ENDC if platform.system() != "Windows" else OchronaLogger.NO
        )
        print(f"{color}[!] {val}{endc}")

    @staticmethod
    def header():
        color = (
            OchronaLogger.INFO if platform.system() != "Windows" else OchronaLogger.NO
        )
        endc = (
            OchronaLogger.ENDC if platform.system() != "Windows" else OchronaLogger.NO
        )
        print(OchronaLogger.HEADER.format(color=color, version=__version__, endc=endc))

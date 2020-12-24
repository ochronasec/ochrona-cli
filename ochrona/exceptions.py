# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""


class OchronaException(Exception):
    pass


class OchronaAPIException(OchronaException):
    pass


class OchronaFileException(OchronaException):
    pass


class OchronaImportException(OchronaException):
    pass

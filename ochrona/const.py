# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

PIPFILE_LOCK = "Pipfile.lock"
POETRY_LOCK = "poetry.lock"
SETUP_PY = "setup.py"
REQUIREMENTS_TXT = "requirements.txt"
CONSTRAINTS_TXT = "constraints.txt"
CONDA_ENVIRONMENT = "environment.yml"
TOX_INI = "tox.ini"

SUPPORTED_DEPENDENCY_FILE_PATTERNS = {
    REQUIREMENTS_TXT: "**/*requirements*.txt",
    CONSTRAINTS_TXT: "**/*constraints*.txt",
    PIPFILE_LOCK: "**/*Pipfile.lock",
    POETRY_LOCK: "**/*poetry.lock",
    SETUP_PY: "**/*setup.py",
    CONDA_ENVIRONMENT: "**/environment.yml",
    TOX_INI: "**/tox.ini",
}

INVALID_REQUIREMENTS_LINES = [
    "#",
    "-i",
    "-f",
    "-Z",
    "--index-url",
    "--extra-index-url",
    "--find-links",
    "--no-index",
    "--allow-external",
    "--allow-unverified",
    "--always-unzip",
]

TOX_LINKED_REQUIREMENTS = "-r"
INVALID_TOX_LINES = ["{"]

INVALID_SPECIFIERS = {"<", ">", "!", "~"}
EQUALS_SPECIFIER = "=="

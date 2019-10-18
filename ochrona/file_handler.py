#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Ochrona-cli
:author: ascott
"""
import json
import os

from ochrona.exceptions import OchronaFileException

SUPPORTED_DEPENDENCY_FILE_PATTERNS = {
    "requirements_txt": "**/*requirements*.txt",
    "pipfile_lock": "**/*Pipfile.lock",
}

PIPFILE_LOCK = "Pipfile.lock"

try:
    from pathlib import Path
except ImportError:
    Path = None


def rfind_all_dependencies_files(logger, directory=None, file=None):
    """
    Recursively searches for dependency files to analyze

    :param logger: A configured `OchronaFormatter` instance
    :param directory: str - starting directory (optional)
    :param file: str - single file to use (optional)
    :return: list - list of paths for files to analyze
    """
    if not directory:
        directory = os.getcwd()

    files = []

    if file:
        files.append(file.name)
    else:
        if Path:
            for filename in Path(directory).glob(
                SUPPORTED_DEPENDENCY_FILE_PATTERNS["requirements_txt"]
            ):
                logger.debug(f"Found matching requirements*.txt file at {filename}")
                files.append(filename)
            for filename in Path(directory).glob(
                SUPPORTED_DEPENDENCY_FILE_PATTERNS["pipfile_lock"]
            ):
                logger.debug(f"Found matching pipfile.lock file at {filename}")
                files.append(filename)
        else:
            # support for pre python 3.5
            pass

    if not files:
        raise OchronaFileException("No dependencies files found")

    return files


def parse_to_payload(logger, file):
    """
    Parses a requirements.txt type file or Pipefile.lock into a JSON payload.
    :param logger: A configured `OchronaFormatter` instance
    :param file: path to file
    :return: JSON payload
    """
    dependencies = []
    if os.path.basename(file).lower() == PIPFILE_LOCK.lower():
        dependencies = _parse_pipfile(file)
    else:
        dependencies = _parse_requirements_file(file)
    logger.debug(f"Discovered dependencies: {dependencies}")
    return json.dumps({"dependencies": dependencies})


def _parse_requirements_file(file):
    """

    :param file:
    :return:
    """
    try:
        with open(file) as file:
            return [line.rstrip("\n") for line in file]
    except OSError as ex:
        raise OchronaFileException(ex)


def _parse_pipfile(file):
    """

    :param file:
    :return: list of dependencies ['dependency==semvar']
    """
    try:
        dependencies = []
        with open(file) as pipfile:
            data = json.load(pipfile)
            if "default" in data:
                for name, value in data["default"].items():
                    dependencies.append(f"{name}{value['version']}")
        return dependencies
    except OSError as ex:
        raise OchronaFileException(ex)

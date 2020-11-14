#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Ochrona-cli
:author: ascott
"""
import ast
import json
import os

import toml

from ochrona.exceptions import OchronaFileException

SUPPORTED_DEPENDENCY_FILE_PATTERNS = {
    "requirements_txt": "**/*requirements*.txt",
    "pipfile_lock": "**/*Pipfile.lock",
    "poetry_lock": "**/*poetry.lock",
    "setup_py": "**/*setup.py",
}

PIPFILE_LOCK = "Pipfile.lock"
POETRY_LOCK = "poetry.lock"
SETUP_PY = "setup.py"

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
            for filename in Path(directory).glob(
                SUPPORTED_DEPENDENCY_FILE_PATTERNS["poetry_lock"]
            ):
                logger.debug(f"Found matching poetry.lock file at {filename}")
                files.append(filename)
            for filename in Path(directory).glob(
                SUPPORTED_DEPENDENCY_FILE_PATTERNS["setup_py"]
            ):
                logger.debug(f"Found matching setup.py file at {filename}")
                files.append(filename)

    if not files:
        raise OchronaFileException("No dependencies files found")

    return files


def parse_to_payload(logger, file, config):
    """
    Parses a requirements.txt type file or Pipefile.lock into a JSON payload.
    :param logger: A configured `OchronaFormatter` instance
    :param file: path to file
    :return: JSON payload
    """
    dependencies = []
    if os.path.basename(file).lower() == PIPFILE_LOCK.lower():
        dependencies = _parse_pipfile(file, config.include_dev)
    elif os.path.basename(file).lower() == POETRY_LOCK.lower():
        dependencies = _parse_poetry(file, config.include_dev)
    elif os.path.basename(file).lower() == SETUP_PY.lower():
        dependencies = _parse_setup_py(file, config.include_dev)
    else:
        dependencies = _parse_requirements_file(file)
    logger.debug(f"Discovered dependencies: {dependencies}")
    if config.project_name is not None:
        return json.dumps(
            {"dependencies": dependencies, "project_name": config.project_name}
        )
    else:
        return json.dumps({"dependencies": dependencies})


def _parse_requirements_file(file):
    """
    Parses a requirements.txt style file into a list of requirements.

    :param file: requirements*.txt file path.
    :return: list<str> list of dependencies ['dependency==semvar']
    """
    try:
        with open(file) as file:
            return [line.rstrip("\n") for line in file]
    except OSError as ex:
        raise OchronaFileException(f"OS error when parsing {file}") from ex


def _parse_pipfile(file, include_dev=False):
    """
    Parses a Pipfile.lock into a list of requirements.

    :param file: Pipfile.lock path
    :return: list<str> list of dependencies ['dependency==semvar']
    """
    try:
        dependencies = []
        with open(file) as pipfile:
            data = json.load(pipfile)
            if "default" in data:
                for name, value in data["default"].items():
                    dependencies.append(f"{name}{value['version']}")
            if "develop" in data and include_dev:
                for name, value in data["develop"].items():
                    dependencies.append(f"{name}{value['version']}")
        return dependencies
    except OSError as ex:
        raise OchronaFileException(f"OS error when parsing {file}") from ex


def _parse_poetry(file, include_dev=False):
    """
    Parses a poetry.lock file into a list of requirements.

    :param file: poetry.lock file path
    :return: list<str> list of dependencies ['dependency==semvar']
    """
    dependencies = []
    try:
        with open(file) as poetry_lock:
            parsed = toml.load(poetry_lock)
            for pkg in parsed.get("package"):
                if pkg.get("category") == "main":
                    dependencies.append(f"{pkg.get('name')}=={pkg.get('version')}")
                elif pkg.get("category") == "dev" and include_dev:
                    dependencies.append(f"{pkg.get('name')}=={pkg.get('version')}")
        return dependencies
    except OSError as ex:
        raise OchronaFileException(f"OS error when parsing {file}") from ex
    except toml.decoder.TomlDecodeError as ex:
        raise OchronaFileException(f"Could not parse {file} - is TOML valid?") from ex


def _parse_setup_py(file, include_dev=False):
    """
    Parses a setup.py into a list of requirements.

    :param file: setup.py path
    :return: list<str> list of dependencies ['dependency==semvar']
    """
    setup_func_names = {"setup", "setuptools.setup"}
    try:
        dependencies = []
        with open(file) as setuppy:
            tree = ast.parse(setuppy.read())
            for body in tree.body:
                if isinstance(body, ast.Expr):
                    if body.value.func.id in setup_func_names:
                        for kw in body.value.keywords:
                            if kw.arg == "install_requires":
                                dependencies += [arg.s for arg in kw.value.elts]
                            elif kw.arg == "tests_require" and include_dev:
                                dependencies += [arg.s for arg in kw.value.elts]
        return dependencies
    except OSError as ex:
        raise OchronaFileException(f"OS error when parsing {file}") from ex
    except AttributeError as ex:
        raise OchronaFileException(f"AST error when parsing {file}") from ex

# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

import ast
import json
import os

from typing import Any, Dict, IO, Optional, List, Type, TextIO
import toml

from ochrona.config import OchronaConfig
from ochrona.const import (
    PIPFILE_LOCK,
    POETRY_LOCK,
    SETUP_PY,
    SUPPORTED_DEPENDENCY_FILE_PATTERNS,
    INVALID_REQUIREMENTS_LINES,
)
from ochrona.exceptions import OchronaFileException
from ochrona.logger import OchronaLogger


Path: Optional[Type] = None
try:
    from pathlib import Path
except ImportError:
    pass


def rfind_all_dependencies_files(
    logger: OchronaLogger,
    directory: Optional[str] = None,
    file_obj: Optional[IO] = None,
) -> List[str]:
    """
    Recursively searches for dependency files to analyze

    :param logger: A configured `OchronaFormatter` instance
    :param directory: str - starting directory (optional)
    :param file_obj: A specified file to use
    :return: list - list of paths for files to analyze
    """
    if not directory:
        directory = os.getcwd()

    files = []

    if file_obj:
        files.append(file_obj.name)
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


def parse_to_payload(
    logger: OchronaLogger, file_path: str, config: OchronaConfig
) -> str:
    """
    Parses a requirements.txt type file or Pipefile.lock into a JSON payload.
    :param logger: A configured `OchronaLogger` instance
    :param file_path: path to file
    :param config: An instance of `OchronaConfig`
    :return: JSON payload
    """
    dependencies = []
    if os.path.basename(file_path).lower() == PIPFILE_LOCK.lower():
        dependencies = _parse_pipfile(file_path, config.include_dev)
    elif os.path.basename(file_path).lower() == POETRY_LOCK.lower():
        dependencies = _parse_poetry(file_path, config.include_dev)
    elif os.path.basename(file_path).lower() == SETUP_PY.lower():
        dependencies = _parse_setup_py(file_path, config.include_dev)
    else:
        dependencies = _parse_requirements_file(file_path)
    logger.debug(f"Discovered dependencies: {dependencies}")
    if config.project_name is not None:
        return json.dumps(
            {"dependencies": dependencies, "project_name": config.project_name}
        )
    else:
        return json.dumps({"dependencies": dependencies})


def _parse_requirements_file(file_path: str) -> List[str]:
    """
    Parses a requirements.txt style file into a list of requirements.

    :param file_path: requirements*.txt file path.
    :return: list<str> list of dependencies ['dependency==semvar']
    """
    try:
        with open(file_path) as rfile:
            deps = [line.rstrip("\n") for line in rfile]
            return [
                dep
                for dep in deps
                if not any([dep.startswith(s) for s in INVALID_REQUIREMENTS_LINES])
            ]
    except OSError as ex:
        raise OchronaFileException(f"OS error when parsing {file_path}") from ex


def _parse_pipfile(file_path: str, include_dev: bool = False) -> List[str]:
    """
    Parses a Pipfile.lock into a list of requirements.

    :param file_path: Pipfile.lock path
    :return: list<str> list of dependencies ['dependency==semvar']
    """
    try:
        dependencies = []
        with open(file_path) as pipfile:
            data = json.load(pipfile)
            if "default" in data:
                for name, value in data["default"].items():
                    dependencies.append(f"{name}{value['version']}")
            if "develop" in data and include_dev:
                for name, value in data["develop"].items():
                    dependencies.append(f"{name}{value['version']}")
        return dependencies
    except OSError as ex:
        raise OchronaFileException(f"OS error when parsing {file_path}") from ex


def _parse_poetry(file_path: str, include_dev: bool = False) -> List[str]:
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
                    dependencies.append(f"{pkg.get('name')}=={pkg.get('version')}")
                elif pkg.get("category") == "dev" and include_dev:
                    dependencies.append(f"{pkg.get('name')}=={pkg.get('version')}")
        return dependencies
    except OSError as ex:
        raise OchronaFileException(f"OS error when parsing {file_path}") from ex
    except toml.decoder.TomlDecodeError as ex:  # type: ignore[attr-defined]
        raise OchronaFileException(
            f"Could not parse {file_path} - is TOML valid?"
        ) from ex


def _parse_setup_py(file_path: str, include_dev: bool = False) -> List[str]:
    """
    Parses a setup.py into a list of requirements.

    :param file_path: setup.py path
    :return: list<str> list of dependencies ['dependency==semvar']
    """
    setup_func_names = {"setup", "setuptools.setup"}
    try:
        dependencies = []
        with open(file_path) as setuppy:
            tree = ast.parse(setuppy.read())
            for body in tree.body:
                if isinstance(body, ast.Expr):
                    if body.value.func.id in setup_func_names:  # type: ignore[attr-defined]
                        for kw in body.value.keywords:  # type: ignore[attr-defined]
                            if kw.arg == "install_requires":
                                dependencies += [arg.s for arg in kw.value.elts]
                            elif kw.arg == "tests_require" and include_dev:
                                dependencies += [arg.s for arg in kw.value.elts]
        return dependencies
    except OSError as ex:
        raise OchronaFileException(f"OS error when parsing {file_path}") from ex
    except AttributeError as ex:
        raise OchronaFileException(f"AST error when parsing {file_path}") from ex

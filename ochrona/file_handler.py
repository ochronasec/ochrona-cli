# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

import os

from typing import Any, Dict, IO, Optional, List, Type, TextIO

from ochrona.config import OchronaConfig
from ochrona.const import (
    CONDA_ENVIRONMENT,
    CONSTRAINTS_TXT,
    PIPFILE_LOCK,
    POETRY_LOCK,
    REQUIREMENTS_TXT,
    SETUP_PY,
    SUPPORTED_DEPENDENCY_FILE_PATTERNS,
    TOX_INI,
)
from ochrona.exceptions import OchronaFileException
from ochrona.logger import OchronaLogger
from ochrona.parsers import Parsers

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
                SUPPORTED_DEPENDENCY_FILE_PATTERNS[REQUIREMENTS_TXT]
            ):
                logger.debug(f"Found matching requirements*.txt file at {filename}")
                files.append(filename)
            for filename in Path(directory).glob(
                SUPPORTED_DEPENDENCY_FILE_PATTERNS[PIPFILE_LOCK]
            ):
                logger.debug(f"Found matching pipfile.lock file at {filename}")
                files.append(filename)
            for filename in Path(directory).glob(
                SUPPORTED_DEPENDENCY_FILE_PATTERNS[POETRY_LOCK]
            ):
                logger.debug(f"Found matching poetry.lock file at {filename}")
                files.append(filename)
            for filename in Path(directory).glob(
                SUPPORTED_DEPENDENCY_FILE_PATTERNS[SETUP_PY]
            ):
                logger.debug(f"Found matching setup.py file at {filename}")
                files.append(filename)
            for filename in Path(directory).glob(
                SUPPORTED_DEPENDENCY_FILE_PATTERNS[CONDA_ENVIRONMENT]
            ):
                logger.debug(f"Found matching conda environment.yml file at {filename}")
                files.append(filename)
            for filename in Path(directory).glob(
                SUPPORTED_DEPENDENCY_FILE_PATTERNS[TOX_INI]
            ):
                logger.debug(f"Found matching conda tox.ini file at {filename}")
                files.append(filename)
            for filename in Path(directory).glob(
                SUPPORTED_DEPENDENCY_FILE_PATTERNS[CONSTRAINTS_TXT]
            ):
                logger.debug(f"Found matching conda constraints.txt file at {filename}")
                files.append(filename)

    if not files:
        raise OchronaFileException("No dependencies files found")

    return files


def parse_to_payload(
    logger: OchronaLogger, file_path: str, config: OchronaConfig
) -> Dict[str, Any]:
    """
    Parses a requirements.txt type file or Pipefile.lock into a JSON payload.
    :param logger: A configured `OchronaLogger` instance
    :param file_path: path to file
    :param config: An instance of `OchronaConfig`
    :return: JSON payload
    """
    dependencies = []
    parsers = Parsers()
    if os.path.basename(file_path).lower() == PIPFILE_LOCK.lower():
        dependencies = parsers.pipfile.parse(
            file_path=file_path, include_dev=config.include_dev
        )
    elif os.path.basename(file_path).lower() == POETRY_LOCK.lower():
        dependencies = parsers.poetry.parse(
            file_path=file_path, include_dev=config.include_dev
        )
    elif os.path.basename(file_path).lower() == SETUP_PY.lower():
        dependencies = parsers.setup.parse(
            file_path=file_path, include_dev=config.include_dev
        )
    elif os.path.basename(file_path).lower() == CONDA_ENVIRONMENT.lower():
        dependencies = parsers.conda.parse(file_path=file_path)
    elif os.path.basename(file_path).lower() == TOX_INI.lower():
        dependencies = parsers.tox.parse(file_path=file_path)
    elif os.path.basename(file_path).lower() == CONSTRAINTS_TXT.lower():
        dependencies = parsers.constraints.parse(file_path=file_path)
    else:
        dependencies = parsers.requirements.parse(file_path=file_path)
    logger.debug(f"Discovered dependencies: {dependencies}")
    if config.project_name is not None:
        return {"dependencies": dependencies, "project_name": config.project_name}
    else:
        return {"dependencies": dependencies}

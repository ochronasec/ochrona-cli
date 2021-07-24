# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

from ochrona.client import pypi_fetch
from ochrona.const import INVALID_SPECIFIERS, EQUALS_SPECIFIER
from ochrona.eval.eval import resolve
from ochrona.exceptions import OchronaImportException
from ochrona.model.confirmed_vulnerability import Vulnerability
from ochrona.model.dependency_set import DependencySet
from ochrona.parser import Parsers
from ochrona.log import OchronaLogger


class SafeImport:
    def __init__(self, logger: OchronaLogger):
        self._logger = logger

    def install(self, package: str):
        """
        Checks a package and if it's safe, imports via pip.

        :param package: a package string with an optional version specified
        :return: bool
        """
        if os.path.isfile(package):
            parsers = Parsers()
            packages = parsers.requirements.parse(package)
            if self._check_package(packages):
                self._logger.info(
                    f"No vulnerabilities found for {', '.join(packages)}, install proceeding."
                )
                self._install_file(package)
            else:
                self._logger.error(
                    f"Import of {', '.join(packages)} aborted due to detected vulnerabilities."
                )
        else:
            if self._check_package(package):
                self._logger.info(
                    f"No vulnerabilities found for {package}, install proceeding."
                )
                self._install(package=package)
            else:
                self._logger.error(
                    f"Import of {package} aborted due to detected vulnerabilities."
                )

    def _check_package(self, package: Union[str, list]) -> bool:
        """
        Calls the analysis API endpoint with a package to see if a package is safe.

        :param package: a package string with an optional version specified
        :return: bool
        """
        vuln_results: DependencySet
        if isinstance(package, str):
            if any(spec in package for spec in INVALID_SPECIFIERS):
                raise OchronaImportException(
                    f"An invalid specifier was found in {package}, either specify the package without a version or pin to a single version using `name==version`."
                )
            parts = package.split(EQUALS_SPECIFIER)
            if len(parts) == 1:
                package = self._get_most_recent_version(package=package)
            vuln_results = resolve(dependencies=[package], logger=self._logger)
        elif isinstance(package, list):
            vuln_results = resolve(dependencies=package, logger=self._logger)
        if len(vuln_results.confirmed_vulnerabilities) > 0:
            self._logger.info(
                f"A full list of packages that would be installed, included dependencies: {', '.join(vuln_results.flat_list)}"
            )
            self._logger.error(
                f"""Vulerabilities found related to import:\n{''.join([self._format_vulnerability(v) for v in vuln_results.confirmed_vulnerabilities])}"""
            )
            return False
        self._logger.info(
            f"A full list of packages to be installed, included dependencies: {', '.join(vuln_results.flat_list)}"
        )
        return True

    def _get_most_recent_version(self, package: str) -> str:
        """
        If a package does not have a version specified we will assume that the latest version
        should be used.

        :param package: a package string without a version
        :return: str
        """
        fetched = pypi_fetch(package=package)
        latest_version = (
            fetched.get("info", {}).get("version", "") if fetched is not None else ""
        )
        if latest_version != "":
            return f"{package}{EQUALS_SPECIFIER}{latest_version}"
        else:
            self._logger.warn("Unable to reach Pypi to confirm latest version")
            return package

    def _install(self, package: str) -> bool:
        """
        Call pip to install a package

        :param package: a package string with a version
        :return: bool
        """
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            return True
        except subprocess.CalledProcessError as ex:
            raise OchronaImportException("Error during pip install") from ex

    def _install_file(self, file_path: str) -> bool:
        """
        Call pip to install a requirements.txt style

        :param file_path: path to requirements file
        :return: bool
        """
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-r", file_path]
            )
            return True
        except subprocess.CalledProcessError as ex:
            raise OchronaImportException("Error during pip install") from ex

    def _format_vulnerability(self, vulnerability: Vulnerability) -> str:
        """
        Formats a vulnerability to a friendly output

        :param vulnerability: vulnerability results
        :return: str
        """
        return f"""\nVulnerability Detected on package to be installed!
    Package: {vulnerability.name}
    ID: {vulnerability.cve_id}
    Description: {vulnerability.description}
    Ochrona Severity: {vulnerability.ochrona_severity_score}
                """

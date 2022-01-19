# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

import sys
from typing import List

from rich import box, print
from rich.table import Table

from ochrona.config import OchronaConfig
from ochrona.log import OchronaLogger
from ochrona.model.confirmed_vulnerability import Vulnerability
from ochrona.model.dependency_set import DependencySet
from ochrona.reporter.reports.base import BaseReport
from ochrona.reporter.reports.basic import BasicReport
from ochrona.reporter.reports.full import FullReport
from ochrona.reporter.reports.html import HTMLReport
from ochrona.reporter.reports.json import JSONReport
from ochrona.reporter.reports.xml import XMLReport


class OchronaReporter:
    def __init__(self, logger: OchronaLogger, config: OchronaConfig):
        self._config = config
        self.logger = logger
        self._report_type = self._config.report_type
        self._report_location = self._config.report_location
        self._exit = self._config.exit
        self._ignore = self._config.ignore

    def report_collector(self, sources: List[str], results: List[DependencySet]):
        """
        Collects and generates each report and exits the program
        :param sources: list of file locations
        :param results: results for each file scan
        :return: sys.exit -1 if vulns are discovered
        """
        reports = []
        if len(sources) == 0:
            sources.append("stdin")
        for index, (source, result) in enumerate(zip(sources, results)):
            if len(result.confirmed_vulnerabilities) > 0:
                result.confirmed_vulnerabilities = list(
                    filter(
                        lambda cv: self._filter_ignored_vuln(cv),
                        result.confirmed_vulnerabilities,
                    )
                )
            else:
                result.confirmed_vulnerabilities = []
            reports.append(self.generate_report(source, result, index, len(sources)))
        for result in results:
            if result.confirmed_vulnerabilities or result.policy_violations:
                if not self._exit:
                    sys.exit(-1)
                sys.exit(0)

    def generate_report(
        self, source: str, result: DependencySet, index: int, total: int
    ):
        """
        Handles report generate based on configured type.

        :param source: str - The source of the data
        :param result: dict - The results from the API
        :param index: int - the index of the file results
        :param total: int - the total number of file results
        :return:
        """
        report_dict = {
            "BASIC": BasicReport.generate,
            "FULL": FullReport.generate,
            "JSON": JSONReport.generate,
            "XML": XMLReport.generate,
            "HTML": HTMLReport.generate,
        }
        report_dict[self._report_type](
            result=result,
            config=self._config,
            source=source,
            total=total,
            index=index,
        )

    def _filter_ignored_vuln(self, confirmed_vuln: Vulnerability) -> bool:
        """
        Returns False is the confirmed vuln matches an ignore rule
        :param confirmed_vuln: dict - Confirmed vulnerability from API results.
        :return: bool
        """
        if not confirmed_vuln or not self._ignore:
            return True
        for cv in self._ignore:
            if cv == confirmed_vuln.cve_id or cv == confirmed_vuln.name:
                return False
        return True

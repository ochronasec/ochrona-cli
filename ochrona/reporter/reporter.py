# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

from dataclasses import asdict
import datetime
import json
import os
import re
import shutil
import sys
import textwrap
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET
from xml.dom import minidom

from rich import box, print
from rich.table import Table

from ochrona.config import OchronaConfig
from ochrona.log import OchronaLogger
from ochrona.model.confirmed_vulnerability import Vulnerability
from ochrona.model.policy_violation import PolicyViolation
from ochrona.model.dependency_set import DependencySet


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
        if self._report_type == "BASIC":
            BaseReport.print_report_number(index, total, self._config.color_output)
            BasicReport.print_findings(
                vulnerabilities=result.confirmed_vulnerabilities,
                violations=result.policy_violations,
                source=source,
                color=self._config.color_output,
            )
        elif self._report_type == "FULL":
            BaseReport.print_report_number(index, total, self._config.color_output)
            FullReport().print_findings(
                vulnerabilities=result.confirmed_vulnerabilities,
                violations=result.policy_violations,
                source=source,
                color=self._config.color_output,
            )
        elif self._report_type == "JSON":
            report = result.confirmed_vulnerabilities
            violations = result.policy_violations

            if report or violations:
                if not self._report_location:
                    BaseReport.print_report_number(
                        index, total, self._config.color_output
                    )
                    JSONReport.display_report(report, violations, source, total, index)
                else:
                    JSONReport.save_report_to_file(
                        report, violations, self._report_location, source, index
                    )
            elif (not report and not violations) and not self._report_location:
                BaseReport.print_report_number(index, total, self._config.color_output)
                JSONReport.display_report(report, violations, source, total, index)
            else:
                JSONReport.save_report_to_file(
                    report, violations, self._report_location, source, index
                )

        elif self._report_type == "XML":
            if not self._report_location:
                BaseReport.print_report_number(index, total, self._config.color_output)
                XMLReport.display_report(result, source, total, index)
            else:
                XMLReport.save_report_to_file(
                    result, self._report_location, source, index
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


class BasicReport(BaseReport):
    """
    Basic Report
        - Includes package name, current version, affected version(s), CPE, Severity

    This report can be logged to stdout
    """

    @staticmethod
    def print_findings(
        vulnerabilities: List[Vulnerability],
        violations: List[PolicyViolation],
        source: str,
        color: bool = True,
    ):
        term_size = shutil.get_terminal_size((100, 20))
        print(f"[bold white italics]File: {source}[/]")
        table = Table(
            box=box.ROUNDED, header_style="bold white", min_width=term_size.columns
        )
        table.add_column(
            header="Vulnerability Check", style="blue bold", justify="right", width=30
        )
        table.add_column(
            header=f"{'[bold red]:cross_mark: {} Vulnerabilities Detected![/]'.format(len(vulnerabilities)) if len(vulnerabilities) > 0 else '[bold green]:white_heavy_check_mark: No Vulnerabilities Detected![/]'}",
            style="blue",
            width=term_size.columns - 30,
        )
        if len(vulnerabilities) > 0:
            for finding in vulnerabilities:
                table.add_row("Package Name", finding.name)
                table.add_row("Installed Version", finding.found_version)
                table.add_row("CVE/Vuln ID", finding.cve_id)
                table.add_row("Severity", f"{finding.ochrona_severity_score}")
                if len(finding.affected_versions) > 0:
                    affected_versions = os.linesep.join(
                        [
                            f"{f.get('operator', '')}{f.get('version_value', '')}"  # type: ignore
                            for f in finding.affected_versions
                        ]
                    )
                    table.add_row(
                        "Affect Versions", affected_versions, end_section=True
                    )
                else:
                    table.add_row(
                        "Affect Versions",
                        finding.vulnerable_version_expression.replace("version", ""),  # type: ignore
                        end_section=True,
                    )
        table.add_row("", "")
        table.add_row(
            "[bold white] Policy Check[/]",
            f"{'[bold red]:cross_mark: {} Policy Violations Found![/]'.format(len(violations)) if len(violations) > 0 else '[bold green]:white_heavy_check_mark: No Policy Violations Found![/]'}",
        )
        for violation in violations:
            table.add_row("Policy", violation.friendly_policy_type)
            table.add_row("Violation", violation.message)
        print(table)


class FullReport(BaseReport):
    """
    Full Report
        - Includes package name, current version, affected version(s), CPE,
                 Severity, Description, References, Publish Date

    This report can be logged to stdout
    """

    @staticmethod
    def print_findings(
        vulnerabilities: List[Vulnerability],
        violations: List[PolicyViolation],
        source: str,
        color: bool = True,
    ):
        term_size = shutil.get_terminal_size((100, 20))
        print(f"[bold white italics]File: {source}[/]")
        table = Table(
            box=box.ROUNDED, header_style="bold white", min_width=term_size.columns
        )
        table.add_column(
            header="Vulnerability Check", style="blue bold", justify="right", width=30
        )
        table.add_column(
            header=f"{'[bold red]:cross_mark: {} Vulnerabilities Detected![/]'.format(len(vulnerabilities)) if len(vulnerabilities) > 0 else '[bold green]:white_heavy_check_mark: No Vulnerabilities Detected![/]'}",
            style="blue",
            width=term_size.columns - 30,
        )
        if len(vulnerabilities) > 0:
            for finding in vulnerabilities:
                table.add_row("Package Name", finding.name)
                table.add_row("Installed Version", finding.found_version)
                table.add_row("Reason", finding.reason)
                table.add_row("CVE/Vuln ID", finding.cve_id)
                table.add_row("Vulnerability Publish Date", finding.publish_date)
                table.add_row("Severity", f"{finding.ochrona_severity_score}")
                table.add_row("Description", finding.description)
                if len(finding.affected_versions) > 0:
                    affected_versions = os.linesep.join(
                        [
                            f"{f.get('operator', '')}{f.get('version_value', '')}"  # type: ignore
                            for f in finding.affected_versions
                        ]
                    )
                    table.add_row("Affect Versions", affected_versions)
                else:
                    table.add_row(
                        "Affect Versions",
                        finding.vulnerable_version_expression.replace("version", ""),  # type: ignore
                    )
                table.add_row("License", finding.license)
                references = os.linesep.join(
                    [f"[magenta underline]{ref}[/]" for ref in finding.references]
                )
                table.add_row("References", references, end_section=True)
        table.add_row("", "")
        table.add_row(
            "[bold white] Policy Check[/]",
            f"{'[bold red]:cross_mark: {} Policy Violations Found![/]'.format(len(violations)) if len(violations) > 0 else '[bold green]:white_heavy_check_mark: No Policy Violations Found![/]'}",
        )
        for violation in violations:
            table.add_row("Policy", violation.friendly_policy_type)
            table.add_row("Violation", violation.message)
        print(table)


class JSONReport(BaseReport):
    """
    JSON report
        - Includes full API findings and metadata in json format.

    This report can be logged to stdout
    """

    @staticmethod
    def display_report(
        result: List[Vulnerability],
        violations: List[PolicyViolation],
        source: str,
        total: int,
        index: int,
    ):
        BaseReport.print_report_source(source)
        print(JSONReport.generate_report_body(result, violations, source))

    @staticmethod
    def save_report_to_file(
        result: List[Vulnerability],
        violations: List[PolicyViolation],
        location: str,
        source: str,
        index: int,
    ):
        with open(
            JSONReport.generate_report_filename(location, source, index), "w"
        ) as f:
            f.write(JSONReport.generate_report_body(result, violations, source))

    @staticmethod
    def generate_report_body(
        result: List[Vulnerability], violations: List[PolicyViolation], source: str
    ) -> str:
        report = {
            "meta": {
                "source": str(source),
                "timestamp": datetime.datetime.now().isoformat(),
            },
            "findings": [asdict(r) for r in result],
            "violations": [asdict(v) for v in violations],
        }
        return json.dumps(report, indent=4)

    @staticmethod
    def generate_report_filename(location: str, source: str, index: int) -> str:
        return f"{location}/{index+1}_{os.path.basename(source).lower()}_results.json"


class XMLReport(BaseReport):
    """
    XML report
        - Includes only discovered vulnerabilities
    This report can be logged to stdout
    """

    VIOLATION_PACKAGE_PATTERN = r"^.*\.\s+\(from (.*)\)$"

    @staticmethod
    def display_report(result: DependencySet, source: str, total: int, index: int):
        BaseReport.print_report_source(source)
        print(XMLReport.generate_report_body(result, source))

    @staticmethod
    def save_report_to_file(
        result: DependencySet, location: str, source: str, index: int
    ):
        with open(
            XMLReport.generate_report_filename(location, source, index), "w"
        ) as f:
            f.write(XMLReport.generate_report_body(result, source))

    @staticmethod
    def generate_report_body(result: DependencySet, source: str) -> str:
        suites = ET.Element("testsuites")
        suite = ET.SubElement(suites, "testsuite")
        suite.set("tests", str(len(result.flat_list)))
        props = ET.SubElement(suite, "properties")
        source_prop = ET.SubElement(props, "property")
        source_prop.set("name", "source")
        source_prop.set("value", str(source))
        ts_prop = ET.SubElement(props, "property")
        ts_prop.set("name", "timestamp")
        ts_prop.set("value", datetime.datetime.now().isoformat())
        for dep in result.flat_list:
            case = ET.SubElement(suite, "testcase")
            case.set("classname", "ochronaDependencyVulnCheck")
            case.set("name", dep)
        if len(result.confirmed_vulnerabilities) > 0:
            for vuln in result.confirmed_vulnerabilities:
                case = list(
                    filter(
                        lambda x: x.get("name") == vuln.found_version,
                        list(suite.iter()),
                    )
                )[0]
                failure = ET.SubElement(case, "failure")
                failure.set("type", "confirmed_vulnerability")
                failure.text = f"Package name: {vuln.name}\nVulnerability description: {vuln.description}\nCVE: {vuln.cve_id}\nSeverity: {vuln.ochrona_severity_score}"
        if len(result.policy_violations) > 0:
            for dep in result.flat_list:
                case = ET.SubElement(suite, "testcase")
                case.set("classname", "ochronaDependencyPolicyCheck")
                case.set("name", dep)
            for violation in result.policy_violations:
                violating_package = re.search(  # type: ignore
                    XMLReport.VIOLATION_PACKAGE_PATTERN, violation.message
                ).groups(1)[0]
                case = list(
                    filter(
                        lambda x: x.get("name") == violating_package
                        and x.get("classname") == "ochronaDependencyPolicyCheck",
                        list(suite.iter()),
                    )
                )[0]
                failure = ET.SubElement(case, "failure")
                failure.set("type", "policy_violations")
                failure.text = violation.message
        return minidom.parseString(ET.tostring(suites)).toprettyxml(indent="   ")

    @staticmethod
    def generate_report_filename(location: str, source: str, index: int) -> str:
        return f"{location}/{index + 1}_{os.path.basename(source).lower()}_results.xml"


class HTMLReport(BaseReport):
    # TODO
    pass

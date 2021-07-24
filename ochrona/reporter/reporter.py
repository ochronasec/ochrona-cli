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
            if result.confirmed_vulnerabilities:
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
        if self._report_type in ["BASIC", "FULL"]:
            BaseReport.print_report_number(index, total, self._config.color_output)
            BaseReport.print_report_source(source, self._config.color_output)
            if not result.confirmed_vulnerabilities:
                BaseReport.print_no_vulns(self._config.color_output)
            else:
                for finding in result.confirmed_vulnerabilities:
                    BasicReport.print_vuln_finding(
                        finding, True, self._config.color_output
                    ) if self._config.report_type == "BASIC" else FullReport.print_vuln_finding(
                        finding, True, self._config.color_output
                    )
                for violation in result.policy_violations:
                    BasicReport.print_policy_violation(violation)
            BaseReport.print_new_line()
        elif self._report_type == "JSON":
            report = result.confirmed_vulnerabilities
            violations = result.policy_violations

            if report or violations:
                if not self._report_location:
                    JSONReport.display_report(report, violations, source, total, index)
                else:
                    JSONReport.save_report_to_file(
                        report, violations, self._report_location, source, index
                    )
            elif (not report and not violations) and not self._report_location:
                JSONReport.display_report(report, violations, source, total, index)
            else:
                JSONReport.save_report_to_file(
                    report, violations, self._report_location, source, index
                )

        elif self._report_type == "XML":
            if not self._report_location:
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
    INFO = "\033[94m"
    PASS = "\033[92m"
    WARNING = "\033[93m"
    ERROR = "\033[91m"
    ENDC = "\033[0m"
    NEWLINE = "\n"
    NO = ""

    @staticmethod
    def print_report_number(index: int, total: int, color: bool = True):
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}Report {index + 1} of {total}{BaseReport.ENDC if color else BaseReport.NO}"
        )

    @staticmethod
    def print_new_line():
        print(BaseReport.NEWLINE)

    @staticmethod
    def print_report_source(source: str, color: bool = True):
        term_size = shutil.get_terminal_size((100, 20))
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}╞{'=' * (term_size.columns-2)}╡{BaseReport.ENDC if color else BaseReport.NO}"
        )
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}| Source: {source}{BaseReport.ENDC if color else BaseReport.NO}"
        )
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}╞{'=' * (term_size.columns-2)}╡{BaseReport.ENDC if color else BaseReport.NO}"
        )

    @staticmethod
    def print_no_vulns(color: bool = True):
        term_size = shutil.get_terminal_size((100, 20))
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}|{BaseReport.PASS if color else BaseReport.NO} ✅  No Vulnerabilities detected{BaseReport.ENDC if color else BaseReport.NO}"
        )
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}╞{'=' * (term_size.columns-2)}╡{BaseReport.ENDC if color else BaseReport.NO}"
        )


class BasicReport(BaseReport):
    """
    Basic Report
        - Includes package name, current version, affected version(s), CPE, Severity

    This report can be logged to stdout
    """

    @staticmethod
    def print_vuln_finding(finding: Vulnerability, confirmed: bool, color: bool = True):
        term_size = shutil.get_terminal_size((100, 20))

        INFO = BaseReport.INFO if color else BaseReport.NO
        ERROR = BaseReport.ERROR if color else BaseReport.NO
        WARNING = BaseReport.WARNING if color else BaseReport.NO
        ENDC = BaseReport.ENDC if color else BaseReport.NO
        ROW_BREAK = f"{INFO}╞{'-' * (term_size.columns-2)}╡{ENDC}"
        LINE_BREAK = f"{INFO}╞{'=' * (term_size.columns-2)}╡{ENDC}"

        if confirmed:
            print(f"{INFO}|{ERROR} ⚠️  Vulnerability Detected!{ENDC}")
            print(ROW_BREAK)
            print(f"{INFO}| Package -- {finding.name}{ENDC}")
            print(ROW_BREAK)
            print(f"{INFO}| Installed Version -- {finding.found_version}{ENDC}")
            print(ROW_BREAK)
            print(f"{INFO}| CVE -- {finding.cve_id}{ENDC}")
            print(ROW_BREAK)
            print(f"{INFO}| Severity -- {finding.ochrona_severity_score} {ENDC}")
            print(ROW_BREAK)
            affected_versions = ", ".join(
                [
                    f"{f.get('operator')}{f.get('version_value')}"  # type: ignore
                    for f in finding.affected_versions
                ]
            )
            print(
                textwrap.fill(
                    f"{INFO}| Affected Versions -- \n| {affected_versions}{ENDC}",
                    (term_size.columns - 2),
                    replace_whitespace=False,
                    initial_indent="",
                    subsequent_indent="| ",
                )
            )
            print(ROW_BREAK)
            print(LINE_BREAK)

    @staticmethod
    def print_policy_violation(violation: PolicyViolation, color: bool = True):
        term_size = shutil.get_terminal_size((100, 20))

        INFO = BaseReport.INFO if color else BaseReport.NO
        ERROR = BaseReport.ERROR if color else BaseReport.NO
        WARNING = BaseReport.WARNING if color else BaseReport.NO
        ENDC = BaseReport.ENDC if color else BaseReport.NO
        ROW_BREAK = f"{INFO}╞{'-' * (term_size.columns-2)}╡{ENDC}"
        LINE_BREAK = f"{INFO}╞{'=' * (term_size.columns-2)}╡{ENDC}"

        print(f"{INFO}|{ERROR} ⚠️  Policy Violation!{ENDC}")
        print(ROW_BREAK)
        print(f"{INFO}| Policy: {violation.friendly_policy_type}{ENDC}")
        print(f"{INFO}| {violation.message}{ENDC}")
        print(ROW_BREAK)
        print(LINE_BREAK)


class FullReport(BaseReport):
    """
    Full Report
        - Includes package name, current version, affected version(s), CPE,
                 Severity, Description, References, Publish Date

    This report can be logged to stdout
    """

    @staticmethod
    def print_vuln_finding(finding: Vulnerability, confirmed: bool, color: bool = True):
        term_size = shutil.get_terminal_size((100, 20))
        INFO = BaseReport.INFO if color else BaseReport.NO
        ERROR = BaseReport.ERROR if color else BaseReport.NO
        WARNING = BaseReport.WARNING if color else BaseReport.NO
        ENDC = BaseReport.ENDC if color else BaseReport.NO
        ROW_BREAK = f"{INFO}╞{'-' * (term_size.columns-2)}╡{ENDC}"
        LINE_BREAK = f"{INFO}╞{'=' * (term_size.columns-2)}╡{ENDC}"

        if confirmed:
            print(f"{INFO}|{ERROR} ⚠️  Vulnerability Detected!{ENDC}")
            print(ROW_BREAK)
            print(f"{INFO}| Package -- {finding.name}{ENDC}")
            print(ROW_BREAK)
            print(f"{INFO}| Installed Version -- {finding.found_version}{ENDC}")
            print(ROW_BREAK)

            print(
                textwrap.fill(
                    f"{INFO}| Reason -- {finding.reason}{ENDC}",
                    (term_size.columns - 2),
                    initial_indent="",
                    subsequent_indent="| ",
                )
            )
            print(ROW_BREAK)
            print(f"{INFO}| CVE -- {finding.cve_id}{ENDC}")
            print(ROW_BREAK)
            print(f"{INFO}| Vulnerability Publish Date -- {finding.publish_date}{ENDC}")
            print(ROW_BREAK)
            print(f"{INFO}| Severity -- {finding.ochrona_severity_score} {ENDC}")
            print(ROW_BREAK)
            print(
                textwrap.fill(
                    f"{INFO}| Description -- {finding.description}{ENDC}",
                    (term_size.columns - 2),
                    initial_indent="",
                    subsequent_indent="| ",
                )
            )
            print(ROW_BREAK)
            print(f"{INFO}| License -- {finding.license} {ENDC}")
            print(ROW_BREAK)
            affected_versions = ", ".join(
                [
                    f"{f.get('operator')}{f.get('version_value')}"  # type: ignore
                    for f in finding.affected_versions
                ]
            )
            print(
                textwrap.fill(
                    f"{INFO}| Affected Version(s) -- \n| {affected_versions}{ENDC}",
                    (term_size.columns - 2),
                    replace_whitespace=False,
                    initial_indent="",
                    subsequent_indent="| ",
                )
            )
            print(ROW_BREAK)
            references = "".join([f"\n| - {ref}" for ref in finding.references])
            print(f"{INFO}| References -- {references}{ENDC}")
            print(LINE_BREAK)
            print(LINE_BREAK)


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
        BaseReport.print_report_number(index, total)
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
        BaseReport.print_report_number(index, total)
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

# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

import datetime
import json
import os
import sys
import textwrap

import xml.etree.ElementTree as ET
from xml.dom import minidom

from typing import Any, Dict, List, Optional

from ochrona.config import OchronaConfig
from ochrona.logger import OchronaLogger


class OchronaReporter:
    def __init__(self, logger: OchronaLogger, config: OchronaConfig):
        self._config = config
        self.logger = logger
        self._report_type = self._config.report_type
        self._report_location = self._config.report_location
        self._exit = self._config.exit
        self._ignore = self._config.ignore

    def report_collector(self, sources: List[str], results: List[Dict[str, Any]]):
        """
        Collects and generates each report and exits the program
        :param sources: list of file locations
        :param results: results for each file scan
        :return: sys.exit -1 if vulns are discovered
        """
        reports = []
        for index, (source, result) in enumerate(zip(sources, results)):
            if "confirmed_vulnerabilities" in result:
                result["confirmed_vulnerabilities"] = list(
                    filter(
                        lambda cv: self._filter_ignored_vuln(cv),
                        result.get("confirmed_vulnerabilities", []),
                    )
                )
            else:
                result["confirmed_vulnerabilities"] = []
            result["potential_vulnerabilities"] = result.get(
                "potential_vulnerabilities", []
            )
            reports.append(self.generate_report(source, result, index, len(sources)))
        for result in results:
            if (
                "confirmed_vulnerabilities" in result
                and result["confirmed_vulnerabilities"]
            ):
                if not self._exit:
                    sys.exit(-1)
                sys.exit(0)

    def generate_report(
        self, source: str, result: Dict[str, Any], index: int, total: int
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
            if (
                not result["confirmed_vulnerabilities"]
                and not result["potential_vulnerabilities"]
            ):
                BaseReport.print_no_vulns(self._config.color_output)
            else:
                # TODO potential_vulnerabilities will be removed
                for finding in result.get("potential_vulnerabilities", []):
                    BasicReport.print_vuln_finding(
                        finding, False, self._config.color_output
                    ) if self._config.report_type == "BASIC" else FullReport.print_vuln_finding(
                        finding, False, self._config.color_output
                    )
                for finding in result.get("confirmed_vulnerabilities", []):
                    BasicReport.print_vuln_finding(
                        finding, True, self._config.color_output
                    ) if self._config.report_type == "BASIC" else FullReport.print_vuln_finding(
                        finding, True, self._config.color_output
                    )
            BaseReport.print_new_line()
        elif self._report_type == "JSON":
            report = result.get("confirmed_vulnerabilities")
            # TODO potential_vulnerabilities will be removed
            if not report:
                report = result.get("potential_vulnerabilities")

            if report:
                if not self._report_location:
                    JSONReport.display_report(report, source, total, index)
                else:
                    JSONReport.save_report_to_file(
                        report, self._report_location, source, index
                    )
            elif not report and not self._report_location:
                JSONReport.display_report([], source, total, index)
            else:
                JSONReport.save_report_to_file([], self._report_location, source, index)
        elif self._report_type == "XML":
            if not self._report_location:
                XMLReport.display_report(result, source, total, index)
            else:
                XMLReport.save_report_to_file(
                    result, self._report_location, source, index
                )

    def _filter_ignored_vuln(self, confirmed_vuln: Dict[str, Any]) -> bool:
        """
        Returns False is the confirmed vuln matches an ignore rule
        :param confirmed_vuln: dict - Confirmed vulnerability from API results.
        :return: bool
        """
        if not confirmed_vuln or not self._ignore:
            return True
        for cv in self._ignore:
            if cv == confirmed_vuln.get("cve_id") or cv == confirmed_vuln.get("name"):
                return False
        return True


class BaseReport:
    INFO = "\033[94m"
    PASS = "\033[92m"
    WARNING = "\033[93m"
    ERROR = "\033[91m"
    ENDC = "\033[0m"
    REPORT_LINE_BREAK = f"{INFO}╞{'=' * 100}╡{ENDC}"
    REPORT_ROW_BREAK = f"{INFO}╞{'-' * 100}╡{ENDC}"
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
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}╞{'=' * 100}╡{BaseReport.ENDC if color else BaseReport.NO}"
        )
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}| Source: {source}{BaseReport.ENDC if color else BaseReport.NO}"
        )
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}╞{'=' * 100}╡{BaseReport.ENDC if color else BaseReport.NO}"
        )

    @staticmethod
    def print_no_vulns(color: bool = True):
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}|{BaseReport.PASS if color else BaseReport.NO} ✅  No Vulnerabilities detected{BaseReport.ENDC if color else BaseReport.NO}"
        )
        print(
            f"{BaseReport.INFO if color else BaseReport.NO}╞{'=' * 100}╡{BaseReport.ENDC if color else BaseReport.NO}"
        )


class BasicReport(BaseReport):
    """
    Basic Report
        - Includes package name, current version, affected version(s), CPE, Severity

    This report can be logged to stdout
    """

    @staticmethod
    def print_vuln_finding(
        finding: Dict[str, Any], confirmed: bool, color: bool = True
    ):
        INFO = BaseReport.INFO if color else BaseReport.NO
        ERROR = BaseReport.ERROR if color else BaseReport.NO
        WARNING = BaseReport.WARNING if color else BaseReport.NO
        ENDC = BaseReport.ENDC if color else BaseReport.NO
        ROW_BREAK = f"{INFO}╞{'-' * 100}╡{ENDC}"
        LINE_BREAK = f"{INFO}╞{'=' * 100}╡{ENDC}"

        if confirmed:
            print(f"{INFO}|{ERROR} ⚠️  Vulnerability Detected!{ENDC}")
        else:
            print(f"{INFO}|{WARNING} ⚠️  [Potential] Vulnerability Detected!{ENDC}")
        print(ROW_BREAK)
        print(f"{INFO}| Package -- {finding.get('name')}{ENDC}")
        print(ROW_BREAK)
        print(f"{INFO}| Installed Version -- {finding.get('found_version')}{ENDC}")
        print(ROW_BREAK)
        print(f"{INFO}| CVE -- {finding.get('cve_id')}{ENDC}")
        print(ROW_BREAK)
        print(f"{INFO}| Severity -- {finding.get('ochrona_severity_score')} {ENDC}")
        print(ROW_BREAK)
        affected_versions = ", ".join(
            [
                f"{f.get('operator')}{f.get('version_value')}"
                for f in finding.get("affected_versions", [])
            ]
        )
        print(
            textwrap.fill(
                f"{INFO}| Affected Versions -- \n{affected_versions}{ENDC}",
                100,
            )
        )
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
    def print_vuln_finding(
        finding: Dict[str, Any], confirmed: bool, color: bool = True
    ):
        INFO = BaseReport.INFO if color else BaseReport.NO
        ERROR = BaseReport.ERROR if color else BaseReport.NO
        WARNING = BaseReport.WARNING if color else BaseReport.NO
        ENDC = BaseReport.ENDC if color else BaseReport.NO
        ROW_BREAK = f"{INFO}╞{'-' * 100}╡{ENDC}"
        LINE_BREAK = f"{INFO}╞{'=' * 100}╡{ENDC}"

        if confirmed:
            print(f"{INFO}|{ERROR} ⚠️  Vulnerability Detected!{ENDC}")
        else:
            print(f"{INFO}|{WARNING} ⚠️  [Potential] Vulnerability Detected!{ENDC}")
        print(ROW_BREAK)
        print(f"{INFO}| Package -- {finding.get('name')}{ENDC}")
        print(ROW_BREAK)
        print(f"{INFO}| Installed Version -- {finding.get('found_version')}{ENDC}")
        print(ROW_BREAK)

        print(
            textwrap.fill(
                f"{INFO}| Reason -- {finding.get('reason')}{ENDC}",
                100,
            )
        )
        print(ROW_BREAK)
        print(f"{INFO}| CVE -- {finding.get('cve_id')}{ENDC}")
        print(ROW_BREAK)
        print(
            f"{INFO}| Vulnerability Publish Date -- {finding.get('publish_date')}{ENDC}"
        )
        print(ROW_BREAK)
        print(f"{INFO}| Severity -- {finding.get('ochrona_severity_score')} {ENDC}")
        print(ROW_BREAK)
        print(
            textwrap.fill(
                f"{INFO}| Description -- {finding.get('description')}{ENDC}",
                100,
            )
        )
        print(ROW_BREAK)
        print(f"{INFO}| License -- {finding.get('license')} {ENDC}")
        print(ROW_BREAK)
        affected_versions = ", ".join(
            [
                f"{f.get('operator')}{f.get('version_value')}"
                for f in finding.get("affected_versions", [])
            ]
        )
        print(
            textwrap.fill(
                f"{INFO}| Affected Version(s) -- \n{affected_versions}{ENDC}",
                100,
            )
        )
        print(ROW_BREAK)
        references = "\n\t".join(finding["references"])
        print(f"{INFO}| References -- \n\t{references} {ENDC}")
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
        result: List[Dict[str, Any]], source: str, total: int, index: int
    ):
        BaseReport.print_report_number(index, total)
        BaseReport.print_report_source(source)
        print(JSONReport.generate_report_body(result, source))

    @staticmethod
    def save_report_to_file(
        result: List[Dict[str, Any]], location: str, source: str, index: int
    ):
        with open(
            JSONReport.generate_report_filename(location, source, index), "w"
        ) as f:
            f.write(JSONReport.generate_report_body(result, source))

    @staticmethod
    def generate_report_body(result: List[Dict[str, Any]], source: str) -> str:
        report = {
            "meta": {
                "source": str(source),
                "timestamp": datetime.datetime.now().isoformat(),
            },
            "findings": result,
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

    @staticmethod
    def display_report(result: Dict[str, Any], source: str, total: int, index: int):
        BaseReport.print_report_number(index, total)
        BaseReport.print_report_source(source)
        print(XMLReport.generate_report_body(result, source))

    @staticmethod
    def save_report_to_file(
        result: Dict[str, Any], location: str, source: str, index: int
    ):
        with open(
            XMLReport.generate_report_filename(location, source, index), "w"
        ) as f:
            f.write(XMLReport.generate_report_body(result, source))

    @staticmethod
    def generate_report_body(result: Dict[str, Any], source: str) -> str:
        suites = ET.Element("testsuites")
        suite = ET.SubElement(suites, "testsuite")
        suite.set("tests", str(len(result.get("flat_list", []))))
        props = ET.SubElement(suite, "properties")
        source_prop = ET.SubElement(props, "property")
        source_prop.set("name", "source")
        source_prop.set("value", str(source))
        ts_prop = ET.SubElement(props, "property")
        ts_prop.set("name", "timestamp")
        ts_prop.set("value", datetime.datetime.now().isoformat())
        for dep in result.get("flat_list", []):
            case = ET.SubElement(suite, "testcase")
            case.set("classname", "ochronaDependencyVulnCheck")
            case.set("name", dep)
        if "confirmed_vulnerabilities" in result:
            for vuln in result.get("confirmed_vulnerabilities", []):
                case = list(
                    filter(
                        lambda x: x.get("name") == vuln.get("found_version"),
                        list(suite.iter()),
                    )
                )[0]
                failure = ET.SubElement(case, "failure")
                failure.set("type", "confirmed_vulnerability")
                failure.text = f"Package name: {vuln.get('name')}\nVulnerability description: {vuln.get('description')}\nCVE: {vuln.get('cve_id')}\nSeverity: {vuln.get('ochrona_severity_score')}"
        return minidom.parseString(ET.tostring(suites)).toprettyxml(indent="   ")

    @staticmethod
    def generate_report_filename(location: str, source: str, index: int) -> str:
        return f"{location}/{index + 1}_{os.path.basename(source).lower()}_results.xml"


class HTMLReport(BaseReport):
    # TODO
    pass

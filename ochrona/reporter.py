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
            BaseReport.print_report_number(index, total)
            BaseReport.print_report_source(source)
            if (
                not result["confirmed_vulnerabilities"]
                and not result["potential_vulnerabilities"]
            ):
                BaseReport.print_no_vulns()
            else:
                # TODO potential_vulnerabilities will be removed
                for finding in result.get("potential_vulnerabilities", []):
                    BasicReport.print_vuln_finding(
                        finding, False
                    ) if self._config.report_type == "BASIC" else FullReport.print_vuln_finding(
                        finding, False
                    )
                for finding in result.get("confirmed_vulnerabilities", []):
                    BasicReport.print_vuln_finding(
                        finding, True
                    ) if self._config.report_type == "BASIC" else FullReport.print_vuln_finding(
                        finding, True
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
            if cv == confirmed_vuln["cve_id"] or cv == confirmed_vuln["name"]:
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

    @staticmethod
    def print_report_number(index: int, total: int):
        print(f"{BaseReport.INFO}Report {index + 1} of {total}{BaseReport.ENDC}")

    @staticmethod
    def print_new_line():
        print(BaseReport.NEWLINE)

    @staticmethod
    def print_report_source(source: str):
        print(BaseReport.REPORT_LINE_BREAK)
        print(f"{BaseReport.INFO}| Source: {source}{BaseReport.ENDC}")
        print(BaseReport.REPORT_LINE_BREAK)

    @staticmethod
    def print_no_vulns():
        print(
            f"{BaseReport.INFO}|{BaseReport.PASS} ✅  No Vulnerabilities detected{BaseReport.ENDC}"
        )
        print(BaseReport.REPORT_LINE_BREAK)


class BasicReport(BaseReport):
    """
    Basic Report
        - Includes package name, current version, affected version(s), CPE, Severity

    This report can be logged to stdout
    """

    @staticmethod
    def print_vuln_finding(finding: Dict[str, Any], confirmed: bool):
        if confirmed:
            print(
                f"{BaseReport.INFO}|{BaseReport.ERROR} ⚠️  Vulnerability Detected!{BaseReport.ENDC}"
            )
        else:
            print(
                f"{BaseReport.INFO}|{BaseReport.WARNING} ⚠️  [Potential] Vulnerability Detected!{BaseReport.ENDC}"
            )
        print(BaseReport.REPORT_ROW_BREAK)
        print(f"{BaseReport.INFO}| Package -- {finding['name']}{BaseReport.ENDC}")
        print(BaseReport.REPORT_ROW_BREAK)
        print(
            f"{BaseReport.INFO}| Installed Version -- {finding['found_version']}{BaseReport.ENDC}"
        )
        print(BaseReport.REPORT_ROW_BREAK)
        print(f"{BaseReport.INFO}| CVE -- {finding['cve_id']}{BaseReport.ENDC}")
        print(BaseReport.REPORT_ROW_BREAK)
        print(
            f"{BaseReport.INFO}| Severity -- {finding['ochrona_severity_score']} {BaseReport.ENDC}"
        )
        print(BaseReport.REPORT_ROW_BREAK)
        affected_versions = ", ".join(
            [
                f"{f['operator']}{f['version_value']}"
                for f in finding["affected_versions"]
            ]
        )
        print(
            textwrap.fill(
                f"{BaseReport.INFO}| Affected Versions -- \n{affected_versions}{BaseReport.ENDC}",
                100,
            )
        )
        print(BaseReport.REPORT_ROW_BREAK)
        print(BaseReport.REPORT_LINE_BREAK)


class FullReport(BaseReport):
    """
    Full Report
        - Includes package name, current version, affected version(s), CPE,
                 Severity, Description, References, Publish Date

    This report can be logged to stdout
    """

    @staticmethod
    def print_vuln_finding(finding: Dict[str, Any], confirmed: bool):
        if confirmed:
            print(
                f"{BaseReport.INFO}|{BaseReport.ERROR} ⚠️  Vulnerability Detected!{BaseReport.ENDC}"
            )
        else:
            print(
                f"{BaseReport.INFO}|{BaseReport.WARNING} ⚠️  [Potential] Vulnerability Detected!{BaseReport.ENDC}"
            )
        print(BaseReport.REPORT_ROW_BREAK)
        print(f"{BaseReport.INFO}| Package -- {finding['name']}{BaseReport.ENDC}")
        print(BaseReport.REPORT_ROW_BREAK)
        print(
            f"{BaseReport.INFO}| Installed Version -- {finding['found_version']}{BaseReport.ENDC}"
        )
        print(BaseReport.REPORT_ROW_BREAK)

        print(
            textwrap.fill(
                f"{BaseReport.INFO}| Reason -- {finding['reason']}{BaseReport.ENDC}",
                100,
            )
        )
        print(BaseReport.REPORT_ROW_BREAK)
        print(f"{BaseReport.INFO}| CVE -- {finding['cve_id']}{BaseReport.ENDC}")
        print(BaseReport.REPORT_ROW_BREAK)
        print(
            f"{BaseReport.INFO}| Vulnerability Publish Date -- {finding['publish_date']}{BaseReport.ENDC}"
        )
        print(BaseReport.REPORT_ROW_BREAK)
        print(
            f"{BaseReport.INFO}| Severity -- {finding['ochrona_severity_score']} {BaseReport.ENDC}"
        )
        print(BaseReport.REPORT_ROW_BREAK)
        print(
            textwrap.fill(
                f"{BaseReport.INFO}| Description -- {finding['description']}{BaseReport.ENDC}",
                100,
            )
        )
        print(BaseReport.REPORT_ROW_BREAK)
        print(f"{BaseReport.INFO}| License -- {finding['license']} {BaseReport.ENDC}")
        print(BaseReport.REPORT_ROW_BREAK)
        affected_versions = ", ".join(
            [
                f"{f['operator']}{f['version_value']}"
                for f in finding["affected_versions"]
            ]
        )
        print(
            textwrap.fill(
                f"{BaseReport.INFO}| Affected Version(s) -- \n{affected_versions}{BaseReport.ENDC}",
                100,
            )
        )
        print(BaseReport.REPORT_ROW_BREAK)
        references = "\n\t".join(finding["references"])
        print(f"{BaseReport.INFO}| References -- \n\t{references} {BaseReport.ENDC}")
        print(BaseReport.REPORT_LINE_BREAK)
        print(BaseReport.REPORT_LINE_BREAK)


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
        suite.set("tests", str(len(result["flat_list"])))
        props = ET.SubElement(suite, "properties")
        source_prop = ET.SubElement(props, "property")
        source_prop.set("name", "source")
        source_prop.set("value", str(source))
        ts_prop = ET.SubElement(props, "property")
        ts_prop.set("name", "timestamp")
        ts_prop.set("value", datetime.datetime.now().isoformat())
        for dep in result["flat_list"]:
            case = ET.SubElement(suite, "testcase")
            case.set("classname", "ochronaDependencyVulnCheck")
            case.set("name", dep)
        if "confirmed_vulnerabilities" in result:
            for vuln in result["confirmed_vulnerabilities"]:
                case = list(
                    filter(
                        lambda x: x.get("name") == vuln["found_version"],
                        list(suite.iter()),
                    )
                )[0]
                failure = ET.SubElement(case, "failure")
                failure.set("type", "confirmed_vulnerability")
                failure.text = f"{vuln['description']}"
        return minidom.parseString(ET.tostring(suites)).toprettyxml(indent="   ")

    @staticmethod
    def generate_report_filename(location: str, source: str, index: int) -> str:
        return f"{location}/{index + 1}_{os.path.basename(source).lower()}_results.xml"


class HTMLReport(BaseReport):
    # TODO
    pass

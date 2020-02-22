#!/usr/bin/env python
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


class OchronaReporter:
    def __init__(self, logger, config):
        self._config = config
        self.logger = logger
        self._report_type = self._config.report_type
        self._report_location = self._config.report_location
        self._exit = self._config.exit
        self._ignore = self._config.ignore

    def report_collector(self, sources, results):
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
                        lambda cv: self._filter_ignored_vulns(cv),
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

    def generate_report(self, source, result, index, total):
        """

        :param source:
        :param result:
        :param index:
        :param total:
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
            report = result.get("confirmed_vulnerabilities", None)
            # TODO potential_vulnerabilities will be removed
            if not report:
                report = result.get("potential_vulnerabilities", None)

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

    def _filter_ignored_vulns(self, c_vulns):
        """

        :param c_vulns:
        :return:
        """
        if not c_vulns or not self._ignore:
            return True
        for cv in self._ignore:
            if cv == c_vulns["cve_id"] or cv == c_vulns["name"]:
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
    def print_report_number(index, total):
        print(f"{BaseReport.INFO}Report {index + 1} of {total}{BaseReport.ENDC}")

    @staticmethod
    def print_new_line():
        print(BaseReport.NEWLINE)

    @staticmethod
    def print_report_source(source):
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
    def print_vuln_finding(finding, confirmed):
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
    def print_vuln_finding(finding, confirmed):
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
    def display_report(result, source, total, index):
        BaseReport.print_report_number(index, total)
        BaseReport.print_report_source(source)
        print(JSONReport.generate_report_body(result, source))

    @staticmethod
    def save_report_to_file(result, location, source, index):
        with open(
            JSONReport.generate_report_filename(location, source, index), "w"
        ) as f:
            f.write(JSONReport.generate_report_body(result, source))

    @staticmethod
    def generate_report_body(result, source):
        report = {
            "meta": {
                "source": str(source),
                "timestamp": datetime.datetime.now().isoformat(),
            },
            "findings": result,
        }
        return json.dumps(report, indent=4)

    @staticmethod
    def generate_report_filename(location, source, index):
        return f"{location}/{index+1}_{os.path.basename(source).lower()}_results.json"


class XMLReport(BaseReport):
    """
    XML report
        - Includes only discovered vulnerabilities
    This report can be logged to stdout
    """

    @staticmethod
    def display_report(result, source, total, index):
        BaseReport.print_report_number(index, total)
        BaseReport.print_report_source(source)
        print(XMLReport.generate_report_body(result, source))

    @staticmethod
    def save_report_to_file(result, location, source, index):
        with open(
            XMLReport.generate_report_filename(location, source, index), "w"
        ) as f:
            f.write(XMLReport.generate_report_body(result, source))

    @staticmethod
    def generate_report_body(result, source):
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
    def generate_report_filename(location, source, index):
        return f"{location}/{index + 1}_{os.path.basename(source).lower()}_results.xml"


class HTMLReport(BaseReport):
    # TODO
    pass

import datetime
import os
import re
import xml.etree.ElementTree as ET
from xml.dom import minidom

from rich import print

from ochrona.config import OchronaConfig
from ochrona.model.dependency_set import DependencySet
from ochrona.reporter.reports.base import BaseReport


class XMLReport(BaseReport):
    """
    XML report
        - Includes only discovered vulnerabilities
    This report can be logged to stdout
    """

    VIOLATION_PACKAGE_PATTERN = r"^Policy violated by (.*)$"

    @staticmethod
    def generate(
        result: DependencySet,
        config: OchronaConfig,
        source: str,
        total: int,
        index: int,
    ):
        if not config.report_location:
            # to stdout
            XMLReport.print_report_number(index, total, config.color_output)
            XMLReport.display_report(result, source, total, index)
        else:
            # to file
            XMLReport.save_report_to_file(result, config.report_location, source, index)

    @staticmethod
    def display_report(result: DependencySet, source: str, total: int, index: int):
        XMLReport.print_report_source(source)
        print(XMLReport.generate_report_body(result, source))

    @staticmethod
    def save_report_to_file(
        result: DependencySet, location: str, source: str, index: int
    ):
        file_path = XMLReport.generate_report_filename(location, source, index)
        with open(file_path, "w") as f:
            f.write(XMLReport.generate_report_body(result, source))
        print(f"Saved output to {file_path}")

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
                ).groups(0)[0]
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
        for violation in result.sast_violations:
            exists = list(
                filter(
                    lambda x: x.get("id") == violation.id
                    and x.get("classname") == "ochronaSASTCheck",
                    list(suite.iter()),
                )
            )
            if len(exists) > 0:
                case = exists[0]
                failure = ET.SubElement(case, "failure")
                failure.set("type", "sast_violation")
                failure.set("location", violation.location)
                failure.set("severity", violation.severity)
                failure.text = violation.message
            else:
                case = ET.SubElement(suite, "testcase")
                case.set("classname", "ochronaSASTCheck")
                case.set("id", violation.id)
                failure = ET.SubElement(case, "failure")
                failure.set("type", "sast_violation")
                failure.set("location", violation.location)
                failure.set("severity", violation.severity)
                failure.text = violation.message
        return minidom.parseString(ET.tostring(suites)).toprettyxml(indent="   ")

    @staticmethod
    def generate_report_filename(location: str, source: str, index: int) -> str:
        return f"{location}/{index + 1}_{os.path.basename(source).lower()}_results.xml"

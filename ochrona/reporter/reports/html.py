import datetime
import os
from pathlib import Path
import pkgutil
from html import escape

from jinja2 import Template

from ochrona.config import OchronaConfig
from ochrona.reporter.reports.base import BaseReport
from ochrona.model.confirmed_vulnerability import Vulnerability
from ochrona.model.dependency_set import DependencySet
from ochrona.model.policy_violation import PolicyViolation
from ochrona.sbom.specs.cyclonedx import CycloneDX


JINJA_TEMPLATE = pkgutil.get_data(__name__, "../../schema/report.html.jinja").decode("utf-8")  # type: ignore


class HTMLReport(BaseReport):
    """
    XML report
        - Includes only discovered vulnerabilities
    This report can be logged to stdout
    """

    @staticmethod
    def generate(
        result: DependencySet,
        config: OchronaConfig,
        source: str,
        total: int,
        index: int,
    ):
        if not config.report_location:
            # write to pwd
            HTMLReport.print_report_number(index, total, config.color_output)
            HTMLReport.save_report_to_file(result, ".", source, index, total)
        else:
            # write to designated location
            HTMLReport.save_report_to_file(
                result, config.report_location, source, index, total
            )

    @staticmethod
    def save_report_to_file(
        result: DependencySet, location: str, source: str, index: int, total: int
    ):
        file_path = HTMLReport.generate_report_filename(location, source, index)
        with open(file_path, "a") as f:
            f.write(HTMLReport.generate_report_body(result, source, index, total))
        print(f"Saved output to {file_path}")

    @staticmethod
    def generate_report_body(
        result: DependencySet, source: str, index: int, total: int
    ) -> str:
        spec = CycloneDX(dependency_set=result)
        policies = [
            PolicyViolation(
                p.policy_type,
                p.friendly_policy_type.replace("Definition: ", ""),
                p.message,
            )
            for p in result.policy_violations
        ]
        data = {
            "file_name": source,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "idx": index + 1,
            "total": total,
            "dependencies": result.dependencies,
            "vulnerabilities": result.confirmed_vulnerabilities,
            "policy_violations": policies,
            "sast_violations": result.sast_violations,
            "sbom": escape(spec.to_xml_string()),
        }
        j2_template = Template(JINJA_TEMPLATE)
        return j2_template.render(data)

    @staticmethod
    def generate_report_filename(location: str, source: str, index: int) -> str:
        return f"{location}/ochrona_results.html"

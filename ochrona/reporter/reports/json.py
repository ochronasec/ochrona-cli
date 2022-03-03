from dataclasses import asdict
import datetime
import json
import os
from typing import List

from rich import print

from ochrona.config import OchronaConfig
from ochrona.model.confirmed_vulnerability import Vulnerability
from ochrona.model.dependency_set import DependencySet
from ochrona.model.policy_violation import PolicyViolation
from ochrona.model.sast_violation import SASTViolation
from ochrona.reporter.reports.base import BaseReport


class JSONReport(BaseReport):
    """
    JSON report
        - Includes full API findings and metadata in json format.

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
        report = result.confirmed_vulnerabilities
        violations = result.policy_violations
        sast_violations = result.sast_violations

        if report or violations:
            if not config.report_location:
                JSONReport.print_report_number(index, total, config.color_output)
                JSONReport.display_report(
                    report, violations, sast_violations, source, total, index
                )
            else:
                JSONReport.save_report_to_file(
                    report,
                    violations,
                    sast_violations,
                    config.report_location,
                    source,
                    index,
                )
        elif (not report and not violations) and not config.report_location:
            JSONReport.print_report_number(index, total, config.color_output)
            JSONReport.display_report(
                report, violations, sast_violations, source, total, index
            )
        else:
            JSONReport.save_report_to_file(
                report,
                violations,
                sast_violations,
                config.report_location,
                source,
                index,
            )

    @staticmethod
    def display_report(
        result: List[Vulnerability],
        violations: List[PolicyViolation],
        sast_violations: List[SASTViolation],
        source: str,
        total: int,
        index: int,
    ):
        JSONReport.print_report_source(source)
        print(
            JSONReport.generate_report_body(result, violations, sast_violations, source)
        )

    @staticmethod
    def save_report_to_file(
        result: List[Vulnerability],
        violations: List[PolicyViolation],
        sast_violations: List[SASTViolation],
        location: str,
        source: str,
        index: int,
    ):
        file_path = JSONReport.generate_report_filename(location, source, index)
        with open(file_path, "w") as f:
            f.write(
                JSONReport.generate_report_body(
                    result, violations, sast_violations, source
                )
            )
        print(f"Saved output to {file_path}")

    @staticmethod
    def generate_report_body(
        result: List[Vulnerability],
        violations: List[PolicyViolation],
        sast_violations: List[SASTViolation],
        source: str,
    ) -> str:
        report = {
            "meta": {
                "source": str(source),
                "timestamp": datetime.datetime.now().isoformat(),
            },
            "findings": [asdict(r) for r in result],
            "violations": [asdict(v) for v in violations],
            "sast_violations": [v.todict() for v in sast_violations],
        }
        return json.dumps(report, indent=4)

    @staticmethod
    def generate_report_filename(location: str, source: str, index: int) -> str:
        return f"{location}/{index+1}_{os.path.basename(source).lower()}_results.json"

import os
import shutil
from typing import List

from rich import box, print
from rich.table import Table

from ochrona.config import OchronaConfig
from ochrona.model.confirmed_vulnerability import Vulnerability
from ochrona.model.dependency_set import DependencySet
from ochrona.model.policy_violation import PolicyViolation
from ochrona.model.sast_violation import SASTViolation
from ochrona.reporter.reports.base import BaseReport


class BasicReport(BaseReport):
    """
    Basic Report
        - Includes package name, current version, affected version(s), CPE, Severity

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
        BasicReport.print_report_number(index, total, config.color_output)
        BasicReport.print_findings(
            vulnerabilities=result.confirmed_vulnerabilities,
            violations=result.policy_violations,
            sast_violations=result.sast_violations,
            source=source,
            color=config.color_output,
        )

    @staticmethod
    def print_findings(
        vulnerabilities: List[Vulnerability],
        violations: List[PolicyViolation],
        sast_violations: List[SASTViolation],
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
        table.add_row(
            "",
            "",
            end_section=True,
        )
        table.add_row(
            "[bold white] Static Code Analysis Results[/]",
            f"{'[bold red]:cross_mark: {} SAST Violations Found![/]'.format(len(sast_violations)) if len(sast_violations) > 0 else '[bold green]:white_heavy_check_mark: No SAST Violations Found![/]'}",
        )
        for sv in sast_violations:
            table.add_row("Plugin ID", sv.id)
            table.add_row("Location", sv.location)
            table.add_row("Violation", sv.message)
            table.add_row("Confidence", sv.confidence)
            table.add_row("Severity", sv.severity)
        print(table)

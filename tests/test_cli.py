import os
from unittest import mock
import pytest

from ochrona.cli import cli
from ochrona.config import OchronaConfig

from click.testing import CliRunner

dir_path = os.path.dirname(os.path.abspath(__file__))

class MockDependencySet:
    def __init__(self, confirmed_vulnerabilities=[], policy_violations=[], flat_list=[]):
        self._confirmed_vulnerabilities = confirmed_vulnerabilities
        self._policy_violations = policy_violations
        self._flat_list = flat_list

    @property
    def confirmed_vulnerabilities(self):
        return self._confirmed_vulnerabilities

    @property
    def policy_violations(self):
        return self._policy_violations

    @property
    def flat_list(self):
        return self._flat_list

class TestCli:
    """
    Component tests for cli module.
    """

    def test_cli_help(self):
        runner = CliRunner()
        help_result = runner.invoke(cli.run, ["--help"])
        assert help_result.exit_code == 0
        assert "--help" in help_result.output

    def test_cli_config_failure(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run, ["--report_type", "FAKE"]
        )
        assert f"Unknown report type specified in FAKE" in result.output

    def test_cli_pass_single_requirements(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--file",
                f"{dir_path}/test_data/pass/requirements.txt",
            ],
        )
        assert result.exit_code == 0

    def test_cli_pass_single_pipfile(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--file",
                f"{dir_path}/test_data/pipfile/Pipfile.lock",
                "--debug"
            ],
        )
        assert result.exit_code == 0

    def test_cli_pass_empty_requirements(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--file",
                f"{dir_path}/test_data/no_op/requirements.txt",
            ],
        )
        assert result.exit_code == 0

    def test_cli_pass_stdin(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "requests==2.22.0",
            ],
        )
        assert result.exit_code == 0

    def test_cli_pass_fail_ignore_package(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--file",
                f"{dir_path}/test_data/fail/requirements.txt",
                "--ignore",
                "requests",
            ],
        )
        assert result.exit_code == 0

    def test_cli_pass_fail_ignore_cve(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--file",
                f"{dir_path}/test_data/fail/requirements.txt",
                "--ignore",
                "CVE-2018-18074",
            ],
        )
        assert result.exit_code == 0

    def test_cli_pass_fail_ignore_no_match(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--file",
                f"{dir_path}/test_data/fail/requirements.txt",
                "--ignore",
                "CVE-2001-1",
            ],
        )
        assert result.exit_code == -1

    @mock.patch("ochrona.importer.SafeImport._check_package")
    @mock.patch("ochrona.importer.SafeImport._install")
    def test_cli_install_vuln(self, install, check):
        check.return_value = False
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            ["--install", "A==1.2.3"],
        )
        check.assert_called_once()
        install.assert_not_called()

    @mock.patch("ochrona.importer.SafeImport._check_package")
    @mock.patch("ochrona.importer.SafeImport._install")
    def test_cli_install_safe(self, install, check):
        check.return_value = True
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            ["--install", "A==1.2.3"],
        )
        check.assert_called_once()
        install.assert_called_once()

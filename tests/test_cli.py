import os
from unittest import mock
import pytest

from ochrona import cli

from click.testing import CliRunner

dir_path = os.path.dirname(os.path.abspath(__file__))


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
        result = runner.invoke(cli.run)
        assert "Missing config value `api_key`" in result.output
        report_result = runner.invoke(
            cli.run, ["--api_key", "1234", "--report_type", "FAKE"]
        )
        assert "Unknown report type specified in FAKE" in report_result.output

    @pytest.mark.vcr()
    def test_cli_fail(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--api_key",
                "1234",
                "--file",
                f"{dir_path}/test_data/fail/requirements.txt",
            ],
        )
        assert result.exit_code == -1

    @pytest.mark.vcr()
    def test_cli_fail_clean_exit(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--api_key",
                "1234",
                "--file",
                f"{dir_path}/test_data/fail/requirements.txt",
                "--exit",
            ],
        )
        assert result.exit_code == 0

    @pytest.mark.vcr()
    def test_cli_pass_single_requirements(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--api_key",
                "1234",
                "--file",
                f"{dir_path}/test_data/pass/requirements.txt",
            ],
        )
        assert result.exit_code == 0

    @pytest.mark.vcr()
    def test_cli_pass_single_pipfile(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--api_key",
                "1234",
                "--file",
                f"{dir_path}/test_data/pipfile/Pipfile.lock",
            ],
        )
        assert result.exit_code == 0

    @pytest.mark.vcr()
    def test_cli_pass_empty_requirements(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--api_key",
                "1234",
                "--file",
                f"{dir_path}/test_data/no_op/requirements.txt",
            ],
        )
        assert result.exit_code == 0

    @pytest.mark.vcr()
    def test_cli_pass_fail_ignore_package(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--api_key",
                "1234",
                "--file",
                f"{dir_path}/test_data/fail/requirements.txt",
                "--ignore",
                "requests",
            ],
        )
        assert result.exit_code == 0

    @pytest.mark.vcr()
    def test_cli_pass_fail_ignore_cve(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--api_key",
                "1234",
                "--file",
                f"{dir_path}/test_data/fail/requirements.txt",
                "--ignore",
                "CVE-2018-18074",
            ],
        )
        assert result.exit_code == 0

    @pytest.mark.vcr()
    def test_cli_pass_fail_ignore_no_match(self):
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--api_key",
                "1234",
                "--file",
                f"{dir_path}/test_data/fail/requirements.txt",
                "--ignore",
                "CVE-2001-1",
            ],
        )
        assert result.exit_code == -1

    @mock.patch("ochrona.ochrona_rest_client.OchronaAPIClient.analyze")
    @mock.patch("ochrona.ochrona_rest_client.OchronaAPIClient.update_alert")
    def test_cli_do_alert_registration(self, alert, analyze):
        analyze.return_value = {
            "confirmed_vulnerabilities": [],
        }

        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--api_key",
                "1234",
                "--file",
                f"{dir_path}/test_data/pass/requirements.txt",
                "--project_name",
                "test_project",
                "--alert_config",
                '{"alerting_addresses": "test@ohrona.dev", "alerting_rules": "not:boto3"}',
            ],
        )
        analyze.assert_called_once()
        alert.assert_called_once()

    @mock.patch("ochrona.ochrona_rest_client.OchronaAPIClient.analyze")
    @mock.patch("ochrona.ochrona_rest_client.OchronaAPIClient.update_alert")
    def test_cli_no_alert_registration(self, alert, analyze):
        analyze.return_value = {
            "confirmed_vulnerabilities": [],
        }

        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            [
                "--api_key",
                "1234",
                "--file",
                f"{dir_path}/test_data/pass/requirements.txt",
                "--project_name",
                "test_project",
            ],
        )
        analyze.assert_called_once()
        alert.assert_not_called()

    @mock.patch("ochrona.import_wrapper.SafeImport._check_package")
    @mock.patch("ochrona.import_wrapper.SafeImport._install")
    def test_cli_install_vuln(self, install, check):
        check.return_value = False
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            ["--api_key", "1234", "--install", "A==1.2.3"],
        )
        check.assert_called_once()
        install.assert_not_called()

    @mock.patch("ochrona.import_wrapper.SafeImport._check_package")
    @mock.patch("ochrona.import_wrapper.SafeImport._install")
    def test_cli_install_safe(self, install, check):
        check.return_value = True
        runner = CliRunner()
        result = runner.invoke(
            cli.run,
            ["--api_key", "1234", "--install", "A==1.2.3"],
        )
        check.assert_called_once()
        install.assert_called_once()

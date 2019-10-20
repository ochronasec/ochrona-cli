import os
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
        assert result.exit_code == 0
        assert "Missing config value `api_key`" in result.output
        report_result = runner.invoke(
            cli.run, ["--api_key", "1234", "--report_type", "FAKE"]
        )
        assert report_result.exit_code == 0
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

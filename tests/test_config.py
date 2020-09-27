import sys

import pytest

from ochrona.config import OchronaConfig


class TestConfig:
    """
    Component tests for config module.
    """

    def test_config_init(self):
        conf = OchronaConfig(api_key="fake", report_type="BASIC")
        assert conf.api_key == "fake"
        assert conf.report_type == "BASIC"

    def test_config_init_alert_parsing(self):
        test_email = "test@ohrona.dev"
        conf = OchronaConfig(
            api_key="fake",
            report_type="BASIC",
            alert_config='{"alerting_addresses": "test@ohrona.dev", "alerting_rules": "not:boto3"}',
        )
        assert conf.api_key == "fake"
        assert conf.report_type == "BASIC"
        assert conf.alert_config.get("alerting_addresses") == test_email
        assert conf.alert_config.get("alerting_rules") == "not:boto3"

    def test_config__validate_invalid_email(self):
        test_email = "test@abc"
        with pytest.raises(SystemExit):
            conf = OchronaConfig(
                api_key="fake",
                report_type="BASIC",
                alert_config='{"alerting_addresses": "test@abc", "alerting_rules": "not:boto3"}',
            )
            valid = conf._validate()
            assert valid[0] is False
            assert valid[1] == f"Invalid email address {test_email} found in config"

    def test_config__validate_missing_alert_email(self):
        with pytest.raises(SystemExit):
            conf = OchronaConfig(
                api_key="fake",
                report_type="BASIC",
                alert_config='{"alerting_rules": "not:boto3"}',
            )
            valid = conf._validate()
            assert valid[0] is True
            assert valid[1] == "Missing alerting_addresses in DADA alert config"

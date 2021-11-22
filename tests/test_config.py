import sys

import pytest

from ochrona.config import OchronaConfig


class TestConfig:
    """
    Component tests for config module.
    """

    def test_config_init_known_report(self):
        conf = OchronaConfig(report_type="BASIC")
        assert conf.report_type == "BASIC"

    def test_config_valid_legacy_poilcy(self):
        conf = OchronaConfig(
            report_type="BASIC",
            policies=[{"policy_type": "package_name", "allow_list": ["allowed"]}]
        )
        valid = conf._validate()
        assert valid[0] is True
        assert valid[1] is None
        assert len(conf.policies) == 1
        assert conf.policies[0].get("policy_type") == "package_name"

    def test_config_init_unknown_report(self):
        fake = "FAKE"
        with pytest.raises(SystemExit) as excinfo:
            conf = OchronaConfig(
                report_type=fake
            )
            valid = conf._validate()
        assert str(excinfo.value) == f"Unknown report type specified as {fake}, allowed: ['BASIC', 'FULL', 'JSON', 'XML']"
    
    def test_config_init_invalid_legacy_policy_type(self):
        with pytest.raises(SystemExit) as excinfo:
            conf = OchronaConfig(
                report_type="BASIC",
                policies=[{"policy_type": "Fake", "allow_list": ["allowed"]}]
            )
            valid = conf._validate()
        assert str(excinfo.value) == "'Fake' is not a supported policy type (package_name, license_type)"
    
    def test_config_init_invalid_legacy_policy_param_dict(self):
        with pytest.raises(SystemExit) as excinfo:
            conf = OchronaConfig(
                report_type="BASIC",
                policies={"policy_type": "Fake", "allow_list": ["allowed"]}
            )
            valid = conf._validate()
        assert str(excinfo.value) == "'policies' must be an array"

    def test_config_init_invalid_legacy_policy_field(self):
        with pytest.raises(SystemExit) as excinfo:
            conf = OchronaConfig(
                report_type="BASIC",
                policies=[{"policy_type": "package_name", "unknown": "unknown"}]
            )
            valid = conf._validate()
        assert str(excinfo.value) == "'package_name' contains an invalid field"

    def test_config_init_invalid_policy(self):
        with pytest.raises(SystemExit) as excinfo:
            conf = OchronaConfig(
                report_type="BASIC",
                policies=["fake"]
            )
            valid = conf._validate()
        assert str(excinfo.value) == "Policy could not be parsed or contains an invalid field."

    def test_config_init_valid_policy(self):
        conf = OchronaConfig(
                report_type="BASIC",
                policies=["license_type==MIT"]
            )
        valid = conf._validate()
        assert valid[0] is True
        assert valid[1] is None
        assert len(conf.policies) == 1
    
    def test_config_init_invalid_policy_field(self):
        with pytest.raises(SystemExit) as excinfo:
            conf = OchronaConfig(
                report_type="BASIC",
                policies=["fake==fake"]
            )
            valid = conf._validate()
        assert str(excinfo.value) == "Policy could not be parsed or contains an invalid field."

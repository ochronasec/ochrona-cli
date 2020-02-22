import sys

from ochrona.config import OchronaConfig


class TestConfig:
    """
    Component tests for config module.
    """

    def test_config(self):
        conf = OchronaConfig(api_key="fake", report_type="BASIC")
        assert conf.api_key == "fake"
        assert conf.report_type == "BASIC"

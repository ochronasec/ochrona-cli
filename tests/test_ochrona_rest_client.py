import os
import pytest

from ochrona.ochrona_rest_client import OchronaAPIClient
from ochrona.exceptions import OchronaAPIException

dir_path = os.path.dirname(os.path.abspath(__file__))


class MockConfig:
    def __init__(self, api_key, api_url, alert_api_url):
        self._api_key = api_key
        self._api_url = api_url
        self._alert_api_url = alert_api_url

    @property
    def api_key(self):
        return self._api_key

    @property
    def api_url(self):
        return self._api_url

    @property
    def alert_api_url(self):
        return self._alert_api_url


class TestAPIClient:
    def test_error_response_handler_4xx(self):
        client = OchronaAPIClient(None, MockConfig("1234", "fake", "fake"))
        with pytest.raises(OchronaAPIException) as ex:
            client._error_response_handler(400)
            assert "Unexpected request sent for analysis. " in ex

    def test_error_response_handler_5xx(self):
        client = OchronaAPIClient(None, MockConfig("1234", "fake", "fake"))
        with pytest.raises(OchronaAPIException) as ex:
            client._error_response_handler(503)
            assert "Unexpected result from analysis, please try again later." in ex

    def test_error_response_handler_3xx(self):
        client = OchronaAPIClient(None, MockConfig("1234", "fake", "fake"))
        with pytest.raises(OchronaAPIException) as ex:
            client._error_response_handler(304)
            assert "Unexpected response from API: 304" in ex

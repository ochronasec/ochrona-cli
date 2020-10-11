#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Ochrona-cli
:author: ascott
"""
import json
import sys
import requests

from ochrona import __version__
from ochrona.exceptions import OchronaAPIException


class OchronaAPIClient:
    def __init__(self, logger, config):
        self._api_key = config.api_key
        self.logger = logger
        self._url = config.api_url
        self._alert_api_url = config.alert_api_url

    def analyze(self, payload=None):
        """
        Calls the analysis API endpoint and returns results.

        :param payload: json payload
        :return: dict
        """
        response = requests.request(
            "POST", self._url, headers=self._generate_headers(), data=payload
        )

        if response.status_code > 300:
            self._error_response_handler(response.status_code)
        else:
            return self._response_handler(response)

    def update_alert(self, payload=None):
        """
        Calls the Alert Registration API to update project alert settings.

        :param payload: json payload
        :return: dict
        """
        response = requests.request(
            "POST",
            self._alert_api_url,
            headers=self._generate_headers(),
            data=self._alert_payload_handler(payload),
        )

        if response.status_code > 300:
            self._error_response_handler(response.status_code)
        else:
            return self._response_handler(response)

    def _generate_headers(self):
        return {
            "Content-Type": "application/json",
            "x-api-key": f"{self._api_key}",
            "User-Agent": f"OchronaClient/{__version__}/{'.'.join([str(i) for i in sys.version_info][0:3])}",
            "Accept": "*/*",
            "Cache-Control": "no-cache",
            "Host": "api.ochrona.dev",
        }

    def _error_response_handler(self, status_code):
        """
        Logs a user friendly message based on the error returned from the server.

        :param status_code: int
        :return:
        """
        if 500 >= status_code >= 400:
            raise OchronaAPIException(
                "Unexpected request sent for analysis. "
                "Please report this at https://github.com/ochronasec/ochrona-cli/issues"
            )
        elif status_code >= 500:
            raise OchronaAPIException(
                "Unexpected result from analysis, please try again later. If this persists, "
                "please report this at https://github.com/ochronasec/ochrona-cli/issues"
            )
        else:
            raise OchronaAPIException(
                "Unexpected response from API: {}".format(status_code)
            )

    def _response_handler(self, response):
        """
        Returns the parsed json response as a dict.

        :param response: Response object from request
        :return: dict
        """
        return json.loads(response.text)

    def _alert_payload_handler(self, config):
        """
        Parses the config object and sends to the Ochrona Alert Registration API.

        :param config: OchronaConfig instance
        :return: dict
        """
        return json.dumps(
            {
                "project_name": config.project_name,
                "alerting_addresses": config.alert_config.get("alerting_addresses"),
                "alerting_rules": config.alert_config.get("alerting_rules"),
            }
        )

# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

import json
import sys
import requests
from typing import Any, Dict, Optional, Union

from ochrona import __version__
from ochrona.config import OchronaConfig
from ochrona.exceptions import OchronaAPIException
from ochrona.logger import OchronaLogger


class OchronaAPIClient:
    def __init__(self, logger: OchronaLogger, config: OchronaConfig):
        self._session_token = config.session_token
        self.logger = logger
        self._url = config.api_url
        self._alert_api_url = config.alert_api_url

    def analyze(self, payload: Optional[str] = None) -> Dict[str, Any]:
        """
        Calls the analysis API endpoint and returns results.

        :param payload: json payload
        :return: dict
        """
        response = requests.request(
            "POST", self._url, headers=self._generate_headers(), data=payload
        )
        if response.status_code > 300:
            self.logger.debug(
                f"Unexpected Response from {self._url} - {response.status_code} - {response.text}"
            )
            self._error_response_handler(response.status_code)
        return self._response_handler(response)

    def update_alert(self, config: Union[Any, OchronaConfig]) -> Dict[str, Any]:
        """
        Calls the Alert Registration API to update project alert settings.

        :param payload: json payload
        :return: dict
        """
        response = requests.request(
            "POST",
            self._alert_api_url,
            headers=self._generate_headers(),
            data=self._alert_payload_handler(config),
        )

        if response.status_code > 300:
            self.logger.debug(
                f"Unexpected Response from {self._alert_api_url} - {response.status_code} - {response.text}"
            )
            self._error_response_handler(response.status_code)
        return self._response_handler(response)

    def _generate_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"{self._session_token}",
            "User-Agent": f"OchronaClient/{__version__}/{'.'.join([str(i) for i in sys.version_info][0:3])}",
            "Accept": "*/*",
            "Cache-Control": "no-cache",
            "Host": "api.ochrona.dev",
        }

    def _error_response_handler(self, status_code: int):
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

    def _response_handler(self, response: requests.models.Response) -> Dict[str, Any]:
        """
        Returns the parsed json response as a dict.

        :param response: Response object from request
        :return: dict
        """
        try:
            return json.loads(response.text)
        except json.JSONDecodeError as ex:
            raise OchronaAPIException("Error parsing API response") from ex

    def _alert_payload_handler(self, config: OchronaConfig) -> str:
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

    def empty_result(self):
        return {
            "confirmed_vulnerabilities": [],
        }

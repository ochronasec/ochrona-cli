# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

import requests

from ochrona.logger import OchronaLogger


class PYPIAPIClient:
    def __init__(self, logger: OchronaLogger):
        self.logger = logger

    def latest_version(self, package: str) -> str:
        """
        Calls pypi to fetch the latest version of a package.

        :param package: package name
        :return: str - latest version
        """
        url = "https://pypi.org/pypi/{}/json".format(package)
        response = requests.request("GET", url)
        if response.status_code == 200:
            json = response.json()
            if json:
                return json.get("info", {}).get("version", "")
        return ""

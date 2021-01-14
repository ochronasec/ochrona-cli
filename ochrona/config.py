# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

import json
import os
import platform
import re
import sys
import yaml
from typing import List, Optional


class OchronaConfig:
    """
    Config for running ochrona cli.
    """

    _api_key: Optional[str] = None
    _debug: bool = False
    _silent: bool = False
    _dir: Optional[str] = None
    _file: Optional[str] = None
    _python_version: Optional[str] = None
    _report_type: Optional[str] = None
    _report_location: Optional[str] = None
    _api_url: Optional[str] = None
    _alert_api_url: Optional[str] = None
    _exit: bool = False
    _ignore: Optional[str] = None
    _include_dev: bool = False
    _color_output: bool = True

    _project_name: Optional[str] = None
    _alert_config: Optional[str] = None

    REPORT_OPTIONS: List[str] = ["BASIC", "FULL", "JSON", "XML"]
    DEFAULT_SL_API_URL: str = "https://api.ochrona.dev/python/analyze"
    DEFAULT_ALERT_API_URL: str = "https://api.ochrona.dev/alerts/project-alerts"

    ALERT_ADDRESS_PATTERN: str = r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$"

    def __init__(self, **kwargs):
        self.get_config(**kwargs)
        valid = self._validate()
        if not valid[0]:
            sys.exit(valid[1])
        self._detect_runtime_attributes()

    def get_config(self, **kwargs):
        """
        Returns a config object for running dependency vulnerability scan.

        Config precedence is:
            1. Command line
            2. Environment Variables
            2. Config
        :param kwargs:
        :return:
        """

        # check command line args
        self._api_key = kwargs.get("api_key")
        self._debug = kwargs.get("debug", False)
        self._silent = kwargs.get("silent", False)
        self._dir = kwargs.get("dir")
        self._file = kwargs.get("file")
        self._report_type = kwargs.get("report_type")
        location = kwargs.get("report_location")
        if location == ".":
            self._report_location = os.getcwd()
        else:
            self._report_location = location
        self._exit = kwargs.get("exit", False)
        self._ignore = kwargs.get("ignore")
        self._include_dev = kwargs.get("include_dev", False)
        self._project_name = kwargs.get("project_name")
        if "alert_config" in kwargs and kwargs.get("alert_config") is not None:
            self._alert_config = json.loads(kwargs.get("alert_config"))

        # check runtime environment
        sys_type = platform.system()
        if sys_type == "Windows":
            self._color_output = False

        # check environment variables
        self._api_key = (
            self._api_key if self._api_key else os.environ.get("OCHRONA_API_KEY", None)
        )
        self._debug = (
            self._debug
            if self._debug
            else os.environ.get("OCHRONA_DEBUG_LOGGING", False)
        )
        self._api_url = os.environ.get(
            "OCHRONA_API_URL", OchronaConfig.DEFAULT_SL_API_URL
        )
        self._alert_api_url = os.environ.get(
            "OCHRONA_ALERT_API_URL", OchronaConfig.DEFAULT_ALERT_API_URL
        )
        self._ignore = (
            self._ignore
            if self._ignore
            else os.environ.get("OCHRONA_IGNORED_VULNS", None)
        )
        if self._ignore:
            self._ignore = self._ignore.split(",")

        # check config .ochrona.yml
        try:
            with open(".ochrona.yml", "r") as stream:
                yaml_loaded = yaml.safe_load(stream)
                if yaml_loaded:
                    self._api_key = yaml_loaded.get("api_key", self._api_key)
                    self._api_url = yaml_loaded.get("api_url", self._api_url)
                    self._alert_api_url = yaml_loaded.get(
                        "alert_url", self._alert_api_url
                    )
                    self._debug = yaml_loaded.get("debug", self._debug)
                    self._silent = yaml_loaded.get("silent", self._silent)
                    self._dir = yaml_loaded.get("dir", self._dir)
                    self._file = (
                        yaml_loaded["file"] if "file" in yaml_loaded else self._file
                    )
                    self._report_type = (
                        yaml_loaded["report_type"]
                        if "report_type" in yaml_loaded
                        else self._report_type
                    )
                    self._report_location = (
                        yaml_loaded["report_location"]
                        if "report_location" in yaml_loaded
                        else self._report_location
                    )
                    self._exit = yaml_loaded.get("exit", self._exit)
                    self._ignore = yaml_loaded.get("ignore", self._ignore)
                    self._include_dev = yaml_loaded.get("include_dev", self._ignore)
                    self._color_output = yaml_loaded.get(
                        "color_output", self._color_output
                    )
                    # Project and DADA configuration
                    self._project_name = yaml_loaded.get(
                        "project_name", self._project_name
                    )
                    if yaml_loaded.get("alert_config") is not None:
                        self._alert_config = {}
                        self._alert_config["alerting_addresses"] = yaml_loaded.get(
                            "alert_config"
                        ).get("alerting_addresses")
                        self._alert_config["alerting_rules"] = yaml_loaded.get(
                            "alert_config"
                        ).get("alerting_rules")
        except IOError:
            pass

    def _validate(self):
        """
        Validates all required values are present.
        """
        if not self._api_key:
            return (False, "Missing config value `api_key`")
        if self._report_type not in self.REPORT_OPTIONS:
            return (False, f"Unknown report type specified in {self._report_type}")
        if self._alert_config is not None:
            if "alerting_addresses" not in self._alert_config:
                return (False, "Missing alerting_addresses in DADA alert config")
            emails = self._alert_config.get("alerting_addresses").split(",")
            if len(emails) <= 0:
                return (
                    False,
                    "alerting_addresses in DADA alert config was found empty",
                )
            for email in emails:
                if not re.match(self.ALERT_ADDRESS_PATTERN, email):
                    return (False, f"Invalid email address {email} found in config")
        return (True, None)

    def _detect_runtime_attributes(self):
        """
        Detects details about the runtime and updates the config.
        """
        self._python_version = ".".join([str(i) for i in sys.version_info][0:3])

    @property
    def api_key(self):
        return self._api_key

    @property
    def debug(self):
        return self._debug

    @property
    def silent(self):
        return self._silent

    @property
    def dir(self):
        return self._dir

    @property
    def file(self):
        return self._file

    @property
    def report_type(self):
        return self._report_type

    @property
    def report_location(self):
        return self._report_location

    @property
    def api_url(self):
        return self._api_url

    @property
    def alert_api_url(self):
        return self._alert_api_url

    @property
    def exit(self):
        return self._exit

    @property
    def ignore(self):
        return self._ignore

    @property
    def include_dev(self):
        return self._include_dev

    @property
    def color_output(self):
        return self._color_output

    @property
    def project_name(self):
        return self._project_name

    @property
    def alert_config(self):
        return self._alert_config

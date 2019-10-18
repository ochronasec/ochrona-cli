#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Ochrona-cli
:author: ascott
"""

import os
import sys
import yaml


class OchronaConfig:
    """
    Config for running ochrona cli.
    """

    _api_key = None
    _debug = False
    _silent = False
    _dir = None
    _file = None
    _python_version = None
    _window_size = None
    _report_type = None
    _report_location = None
    _api_url = None
    _exit = None

    REPORT_OPTIONS = ["BASIC", "FULL", "JSON", "XML"]
    DEFAULT_API_URL = "https://api.ochrona.dev/python/analyze"

    def __init__(self, **kwargs):
        self.get_config(**kwargs)
        self._validate()

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
        if "api_key" in kwargs:
            self._api_key = kwargs.get("api_key", None)
        if "debug" in kwargs:
            self._debug = kwargs.get("debug", False)
        if "silent" in kwargs:
            self._silent = kwargs.get("silent", False)
        if "dir" in kwargs:
            self._dir = kwargs.get("dir", None)
        if "file" in kwargs:
            self._file = kwargs.get("file", None)
        if "report_type" in kwargs:
            self._report_type = kwargs.get("report_type", None)
        if "report_location" in kwargs:
            location = kwargs.get("report_location", None)
            if location == ".":
                self._report_location = os.getcwd()
            else:
                self._report_location = location
        if "exit" in kwargs:
            self._exit = kwargs.get("exit", False)

        # check environment variables
        self._api_key = (
            self._api_key if self._api_key else os.environ.get("OCHRONA_API_KEY", None)
        )
        self._debug = (
            self._debug
            if self._debug
            else os.environ.get("OCHRONA_DEBUG_LOGGING", False)
        )
        self._api_url = os.environ.get("OCHRONA_API_URL", OchronaConfig.DEFAULT_API_URL)

        # check config .ochrona.yml
        try:
            with open(".ochrona.yml", "r") as stream:
                yaml_loaded = yaml.safe_load(stream)
                if yaml_loaded:
                    self._api_key = (
                        yaml_loaded["api_key"]
                        if "api_key" in yaml_loaded
                        else self._api_key
                    )
                    self._api_url = (
                        yaml_loaded["api_url"]
                        if "api_url" in yaml_loaded
                        else self._api_url
                    )
                    self._debug = (
                        yaml_loaded["debug"] if "debug" in yaml_loaded else self._debug
                    )
                    self._silent = (
                        yaml_loaded["silent"]
                        if "silent" in yaml_loaded
                        else self._silent
                    )
                    self._dir = (
                        yaml_loaded["dir"] if "dir" in yaml_loaded else self._dir
                    )
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
                    self._exit = (
                        yaml_loaded["exit"] if "exit" in yaml_loaded else self._exit
                    )
        except IOError:
            pass

    def _validate(self):
        """
        Validates all required values are present.
        """
        if not self._api_key:
            print("Missing config value `api_key`")
            sys.exit(0)
        if self._report_type not in self.REPORT_OPTIONS:
            print(f"Unknown report type specified in {self._report_type}")
            sys.exit(0)

    def _detect_runtime_attributes(self):
        """
        Detects details about the runtime and updates the config.
        """
        self._window_size = os.get_terminal_size()
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
    def exit(self):
        return self._exit

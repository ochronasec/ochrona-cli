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
from typing import Any, Dict, List, Optional, Tuple

from ochrona.eval.policy import POLICY_SCHEMAS
from ochrona.eval.policy.validator import validate


class OchronaConfig:
    """
    Config for running ochrona cli.
    """

    _debug: bool = False
    _silent: bool = False
    _dir: Optional[str] = None
    _exclude_dir: Optional[List[str]] = None
    _file: Optional[str] = None
    _python_version: Optional[str] = None
    _report_type: Optional[str] = None
    _report_location: Optional[str] = None
    _exit: bool = False
    _ignore: Optional[List[str]] = None
    _include_dev: bool = False
    _color_output: bool = True
    _policies: List[Dict[str, Any]] = []

    REPORT_OPTIONS: List[str] = ["BASIC", "FULL", "JSON", "XML"]

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
        self._debug = kwargs.get("debug", False)
        self._silent = kwargs.get("silent", False)
        self._dir = kwargs.get("dir")
        self._exclude_dir = kwargs.get("exclude_dir")
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
        self._policies = kwargs.get("policies", [])

        # check runtime environment
        sys_type = platform.system()
        if sys_type == "Windows":
            self._color_output = False

        # check environment variables
        self._debug = (
            self._debug
            if self._debug
            else os.environ.get("OCHRONA_DEBUG_LOGGING", False)
        )
        self._ignore = (
            self._ignore
            if self._ignore
            else os.environ.get("OCHRONA_IGNORED_VULNS", None)
        )
        if self._ignore:
            self._ignore = (
                self._ignore.split(",")
                if isinstance(self._ignore, str)
                else self._ignore
            )

        if self._exclude_dir:
            self._exclude_dir = (
                self._exclude_dir.split(",")
                if isinstance(self._exclude_dir, str)
                else self._exclude_dir
            )

        # check config .ochrona.yml
        try:
            with open(".ochrona.yml", "r") as stream:
                yaml_loaded = yaml.safe_load(stream)
                if yaml_loaded:
                    self._debug = yaml_loaded.get("debug", self._debug)
                    self._silent = yaml_loaded.get("silent", self._silent)
                    self._dir = yaml_loaded.get("dir", self._dir)
                    self._exclude_dir = yaml_loaded.get(
                        "exclude_dir", self._exclude_dir
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
                    self._exit = yaml_loaded.get("exit", self._exit)
                    self._ignore = yaml_loaded.get("ignore", self._ignore)
                    self._include_dev = yaml_loaded.get(
                        "include_dev", self._include_dev
                    )
                    self._color_output = yaml_loaded.get(
                        "color_output", self._color_output
                    )
                    self._policies = yaml_loaded.get("policies")
        except IOError:
            pass

    def _validate(self) -> Tuple[bool, Optional[str]]:
        """
        Validates all required values are present.
        """
        if self._report_type not in self.REPORT_OPTIONS:
            return (False, f"Unknown report type specified in {self._report_type}")
        if len(self._policies) > 0:
            return self._validate_policies()
        return (True, None)

    def _detect_runtime_attributes(self):
        """
        Detects details about the runtime and updates the config.
        """
        self._python_version = ".".join([str(i) for i in sys.version_info][0:3])

    def _validate_policies(self) -> Tuple[bool, Optional[str]]:
        """
        Validates any provided policies
        """
        if not isinstance(self._policies, list):
            return (False, "'policies' must be an array")
        for policy in self._policies:
            # PENDING-DEPRECATION
            # "legacy" policies will be removed in a future release
            if isinstance(policy, dict):
                if policy.get("policy_type") not in POLICY_SCHEMAS:
                    return (
                        False,
                        f"'{policy.get('policy_type')}' is not a supported policy type ({', '.join(POLICY_SCHEMAS.keys())})",
                    )
                policy_keys = list(policy.keys())
                for key in policy_keys:
                    if key != "policy_type" and key not in POLICY_SCHEMAS.get(
                        policy.get("policy_type", {}), {}
                    ).get("fields"):
                        return (
                            False,
                            f"'{policy.get('policy_type')}' contains an invalid field",
                        )
            elif isinstance(policy, str):
                results = validate(policy)
                if not results[0]:
                    return results
            else:
                return (False, "'policies' entries must be objects or strings")
        return (True, None)

    @property
    def debug(self) -> bool:
        return self._debug

    @property
    def silent(self) -> bool:
        return self._silent

    @property
    def dir(self):
        return self._dir

    @property
    def exclude_dir(self):
        return self._exclude_dir

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
    def policies(self):
        return self._policies

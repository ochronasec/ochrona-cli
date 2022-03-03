import sys

import pytest

import ochrona.eval.eval as e
from ochrona.model.dependency_set import DependencySet


class MockLogger:
    def __init__(self):
        self._debug = []
        self._info = []
        self._warn = []
        self._error = []

    def debug(self, msg):
        self._debug.append(msg)

    def info(self, msg):
        self._info.append(msg)

    def warn(self, msg):
        self._warn.append(msg)

    def error(self, msg):
        self._error.append(msg)

class MockConfig:

    def __init__(self, enable_sast=False, policies=[]):
        self._enable_sast = enable_sast
        self._policies = policies

    @property
    def enable_sast(self):
        return self._enable_sast

    @property
    def policies(self):
        return self._policies

class TestEval:
    """
    Component tests for eval.eval module.
    """
    def test_resolve(self):
        res = e.resolve(logger=MockLogger(), config=MockConfig())
        assert isinstance(res, DependencySet)
        assert res.dependencies == []
        assert res.flat_list == []
        assert res.confirmed_vulnerabilities == []
        assert res.policy_violations == []

    def test_resolve_no_vulns(self):
        res = e.resolve(dependencies=[{"version": "fake==9.9.9"}], logger=MockLogger(), config=MockConfig())
        assert isinstance(res, DependencySet)
        assert len(res.dependencies) == 1
        assert res.flat_list == ["fake==9.9.9"]
        assert res.confirmed_vulnerabilities == []
        assert res.policy_violations == []

    def test_resolve_vuln_found(self):
        res = e.resolve(dependencies=[{"version": "requests==2.19.0"}], logger=MockLogger(), config=MockConfig())
        assert isinstance(res, DependencySet)
        assert len(res.dependencies) == 1
        assert res.flat_list == ["requests==2.19.0"]
        assert len(res.confirmed_vulnerabilities) == 1
        assert res.confirmed_vulnerabilities[0].cve_id == "CVE-2018-18074"
        assert res.policy_violations == []

    def test_resolve_policy_violation(self):
        conf = MockConfig(policies=["name IN requests,click,pytest"])
        res = e.resolve(dependencies=[{"version": "fake==9.9.9"}], logger=MockLogger(), config=conf)
        assert isinstance(res, DependencySet)
        assert len(res.dependencies) == 1
        assert res.flat_list == ["fake==9.9.9"]
        assert res.confirmed_vulnerabilities == []
        assert len(res.policy_violations) == 1
        assert res.policy_violations[0].message == "Policy violated by fake==9.9.9"

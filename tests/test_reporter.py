import os
import json
import xml.etree.ElementTree as ET
import pytest

from ochrona.reporter import OchronaReporter
from ochrona.model.confirmed_vulnerability import Vulnerability
from ochrona.model.policy_violation import PolicyViolation

dir_path = os.path.dirname(os.path.abspath(__file__))


class MockConfig:
    def __init__(self, report_type, location, exit_=False, ignore=None, color_output=False):
        self._report_type = report_type
        self._location = location
        self._exit = exit_
        self._ignore = ignore
        self._color_output = color_output

    @property
    def report_type(self):
        return self._report_type

    @property
    def report_location(self):
        return self._location

    @property
    def exit(self):
        return self._exit

    @property
    def ignore(self):
        return self._ignore

    @property
    def color_output(self):
        return self._color_output


class MockDependencySet:
    def __init__(self, confirmed_vulnerabilities=[], policy_violations=[], flat_list=[], dependencies=[]):
        self._confirmed_vulnerabilities = confirmed_vulnerabilities
        self._policy_violations = policy_violations
        self._flat_list = flat_list
        self._dependencies = dependencies

    @property
    def confirmed_vulnerabilities(self):
        return self._confirmed_vulnerabilities

    @property
    def policy_violations(self):
        return self._policy_violations

    @property
    def flat_list(self):
        return self._flat_list
    
    @property
    def dependencies(self):
        return self._dependencies


class TestOchronaReporter:
    def test_generate_empty_json_stdout(self, capsys):
        conf = MockConfig(
            "JSON",
            None,
        )
        reporter = OchronaReporter(None, conf)
        reporter.generate_report("fake", MockDependencySet(), 0, 1)
        captured = capsys.readouterr()
        assert "File: fake" in captured.out
        assert '"findings": []' in captured.out

    def test_generate_json_stdout(self, capsys):
        conf = MockConfig("JSON", None)
        result = MockDependencySet()
        vuln = Vulnerability("fake", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
        result._confirmed_vulnerabilities = [vuln]
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            "fake", result, 0, 1
        )
        captured = capsys.readouterr()
        assert "File: fake" in captured.out
        assert '"name": "fake"' in captured.out

    def test_generate_empty_json_file(self):
        conf = MockConfig("JSON", f"{dir_path}/test_data/output")
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            f"{dir_path}/test_data/fail/requirements.txt", MockDependencySet(), 0, 1
        )
        with open(
            f"{dir_path}/test_data/output/1_requirements.txt_results.json", "r"
        ) as out:
            output = json.loads(out.read())
            assert not output["findings"], "expected 0 findings"
            assert (
                output["meta"]["source"]
                == f"{dir_path}/test_data/fail/requirements.txt"
            )
        os.remove(f"{dir_path}/test_data/output/1_requirements.txt_results.json")

    def test_generate_json_file(self):
        conf = MockConfig("JSON", f"{dir_path}/test_data/output")
        result = MockDependencySet()
        vuln = Vulnerability("fake", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
        result._confirmed_vulnerabilities = [vuln]
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            f"{dir_path}/test_data/fail/requirements.txt",
            result,
            0,
            1,
        )
        with open(
            f"{dir_path}/test_data/output/1_requirements.txt_results.json", "r"
        ) as out:
            output = json.loads(out.read())
            assert len(output["findings"]) == 1, "expected 1 finding"
            assert (
                output["meta"]["source"]
                == f"{dir_path}/test_data/fail/requirements.txt"
            )
        os.remove(f"{dir_path}/test_data/output/1_requirements.txt_results.json")

    def test_generate_empty_xml_stdout(self, capsys):
        conf = MockConfig("XML", None)
        reporter = OchronaReporter(None, conf)
        reporter.generate_report("fake", MockDependencySet(), 0, 1)
        captured = capsys.readouterr()
        assert '<testsuite tests="0">' in captured.out

    def test_generate_xml_stdout(self, capsys):
        conf = MockConfig("XML", None)
        result = MockDependencySet()
        vuln = Vulnerability("fake", "123", "", "", "", "", "", "fake finding", "", "", "", "8.4", "fake", "", "", "", "", "")
        result._confirmed_vulnerabilities = [vuln]
        result._flat_list = ["fake"]
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            "fake",
            result,
            0,
            1,
        )
        captured = capsys.readouterr()
        assert '<testsuite tests="1">' in captured.out
        assert (
            '<failure type="confirmed_vulnerability">Package name: fake\nVulnerability description: fake finding\nCVE: 123\nSeverity: 8.4</failure>'
            in captured.out
        )

    def test_generate_empty_xml_file(self):
        conf = MockConfig("XML", f"{dir_path}/test_data/output")
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            f"{dir_path}/test_data/fail/requirements.txt", MockDependencySet(), 0, 1
        )
        with open(
            f"{dir_path}/test_data/output/1_requirements.txt_results.xml", "r"
        ) as out:
            output = ET.parse(out)
            for entry in output.getroot():
                assert entry.get("tests") == "0", "expected 0 findings"
        os.remove(f"{dir_path}/test_data/output/1_requirements.txt_results.xml")

    def test_generate_xml_file(self):
        conf = MockConfig("XML", f"{dir_path}/test_data/output")
        result = MockDependencySet()
        vuln = Vulnerability("fake", "123", "", "", "", "", "", "fake finding", "", "", "", "8.4", "fake", "", "", "", "", "")
        result._confirmed_vulnerabilities = [vuln]
        pv = PolicyViolation("custom", "Definition: license_type == MIT", "Policy violated by fake")
        result._policy_violations = [pv]
        result._flat_list = ["fake"]
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            f"{dir_path}/test_data/fail/requirements.txt",
            result,
            0,
            1,
        )
        with open(
            f"{dir_path}/test_data/output/1_requirements.txt_results.xml", "r"
        ) as out:
            output = ET.parse(out)
            for entry in output.getroot():
                assert entry.get("tests") == "1", "expected 1 finding"
        os.remove(f"{dir_path}/test_data/output/1_requirements.txt_results.xml")

    def test_generate_html_file(self):
        conf = MockConfig("HTML", f"{dir_path}/test_data/output")
        result = MockDependencySet()
        vuln = Vulnerability("fake", "123", "", "", "", "", "", "fake finding", "", "", "", "8.4", "fake", "", "", "", "", "")
        result._confirmed_vulnerabilities = [vuln]
        result._flat_list = ["fake"]
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            f"{dir_path}/test_data/fail/requirements.txt",
            result,
            0,
            1,
        )
        with open(
            f"{dir_path}/test_data/output/ochrona_results.html", "r"
        ) as out:
            output = out.read()
            assert f"{dir_path}/test_data/fail/requirements.txt" in output
        os.remove(f"{dir_path}/test_data/output/ochrona_results.html")

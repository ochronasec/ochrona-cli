import os
import json
import xml.etree.ElementTree as ET
import pytest

from ochrona.reporter import OchronaReporter
from ochrona.model.confirmed_vulnerability import Vulnerability

dir_path = os.path.dirname(os.path.abspath(__file__))


class MockConfig:
    def __init__(self, report_type, location, exit_=False, ignore=None):
        self._report_type = report_type
        self._location = location
        self._exit = exit_
        self._ignore = ignore

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


class MockDependencySet:
    def __init__(self, confirmed_vulnerabilities=[], policy_violations=[], flat_list=[]):
        self._confirmed_vulnerabilities = confirmed_vulnerabilities
        self._policy_violations = policy_violations
        self._flat_list = flat_list

    @property
    def confirmed_vulnerabilities(self):
        return self._confirmed_vulnerabilities

    @property
    def policy_violations(self):
        return self._policy_violations

    @property
    def flat_list(self):
        return self._flat_list

# class MockVulnerability:
#     def __init__(self, name, found_version=None, description=None, cve_id=None, ochrona_severity_score=None):
#         self._name = name
#         self._found_version = found_version
#         self._description = description
#         self._cve_id = cve_id
#         self._ochrona_severity_score = ochrona_severity_score

#     @property
#     def name(self):
#         return self._name

#     @property
#     def found_version(self):
#         return self._found_version

#     @property
#     def description(self):
#         return self._description

#     @property
#     def cve_id(self):
#         return self._cve_id

#     @property
#     def ochrona_severity_score(self):
#         return self._ochrona_severity_score

#     def asdict(self):
#         return {
#             "name": self.name,
#             "found_version": self.found_version,
#             "description": self.description,
#             "cve_id": self.cve_id,
#             "ochrona_severity_score": self.ochrona_severity_score
#         }

class TestOchronaReporter:
    def test_generate_empty_json_stdout(self, capsys):
        conf = MockConfig(
            "JSON",
            None,
        )
        reporter = OchronaReporter(None, conf)
        reporter.generate_report("fake", MockDependencySet(), 0, 1)
        captured = capsys.readouterr()
        assert "Source: fake" in captured.out
        assert '"findings": []' in captured.out

    def test_generate_json_stdout(self, capsys):
        conf = MockConfig("JSON", None)
        result = MockDependencySet()
        vuln = Vulnerability("fake", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
        result._confirmed_vulnerabilities = [vuln]
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            "fake", result, 0, 1
        )
        captured = capsys.readouterr()
        assert "Source: fake" in captured.out
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
        vuln = Vulnerability("fake", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "")
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
        vuln = Vulnerability("fake", "123", "", "", "", "", "", "fake finding", "", "", "", "8.4", "fake", "", "", "", "")
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
        vuln = Vulnerability("fake", "123", "", "", "", "", "", "fake finding", "", "", "", "8.4", "fake", "", "", "", "")
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
            f"{dir_path}/test_data/output/1_requirements.txt_results.xml", "r"
        ) as out:
            output = ET.parse(out)
            for entry in output.getroot():
                assert entry.get("tests") == "1", "expected 1 finding"
        os.remove(f"{dir_path}/test_data/output/1_requirements.txt_results.xml")

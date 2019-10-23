import os
import json
import xml.etree.ElementTree as ET
import pytest

from ochrona.reporter import OchronaReporter

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


class TestOchronaReporter:
    def test_generate_empty_json_stdout(self, capsys):
        conf = MockConfig("JSON", None, )
        reporter = OchronaReporter(None, conf)
        reporter.generate_report("fake", {}, 0, 1)
        captured = capsys.readouterr()
        assert "Source: fake" in captured.out
        assert '"findings": []' in captured.out

    def test_generate_json_stdout(self, capsys):
        conf = MockConfig("JSON", None)
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            "fake", {"confirmed_vulnerabilities": [{"name": "fake"}]}, 0, 1
        )
        captured = capsys.readouterr()
        assert "Source: fake" in captured.out
        assert '"name": "fake"' in captured.out

    def test_generate_empty_json_file(self):
        conf = MockConfig("JSON", f"{dir_path}/test_data/output")
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            f"{dir_path}/test_data/fail/requirements.txt", {}, 0, 1
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
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            f"{dir_path}/test_data/fail/requirements.txt",
            {"confirmed_vulnerabilities": [{"name": "fake"}]},
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
        reporter.generate_report("fake", {"flat_list": []}, 0, 1)
        captured = capsys.readouterr()
        assert '<testsuite tests="0">' in captured.out

    def test_generate_xml_stdout(self, capsys):
        conf = MockConfig("XML", None)
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            "fake",
            {
                "flat_list": ["fake"],
                "confirmed_vulnerabilities": [
                    {"found_version": "fake", "description": "fake finding"}
                ],
            },
            0,
            1,
        )
        captured = capsys.readouterr()
        assert '<testsuite tests="1">' in captured.out
        assert (
            '<failure type="confirmed_vulnerability">fake finding</failure>'
            in captured.out
        )

    def test_generate_empty_xml_file(self):
        conf = MockConfig("XML", f"{dir_path}/test_data/output")
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            f"{dir_path}/test_data/fail/requirements.txt", {"flat_list": []}, 0, 1
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
        reporter = OchronaReporter(None, conf)
        reporter.generate_report(
            f"{dir_path}/test_data/fail/requirements.txt",
            {
                "flat_list": ["fake"],
                "confirmed_vulnerabilities": [
                    {"found_version": "fake", "description": "fake finding"}
                ],
            },
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

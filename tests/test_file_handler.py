import os
import pytest
from json import loads

from ochrona.file_handler import (
    rfind_all_dependencies_files,
    parse_to_payload,
    parse_direct_to_payload,
)
from ochrona.exceptions import OchronaFileException

dir_path = os.path.dirname(os.path.abspath(__file__))


class MockLogger:
    def __init__(self):
        self._logged = []

    def debug(self, msg):
        self._logged.append(msg)


class MockConfig:

    _include_dev = False
    _project_name = ""

    @property
    def include_dev(self):
        return self._include_dev

    @property
    def project_name(self):
        return self._project_name


class TestFileHandlerRfindAllDependenciesFiles:
    """
    Unit tests for file_handler:rfind_all_dependencies_files method.
    """

    def test_single_requirements(self):
        with open(f"{dir_path}/test_data/fail/requirements.txt", "r") as file:
            files = rfind_all_dependencies_files(MockLogger(), None, None, file)
            assert len(files) == 1, "Expected to find a single file"

    def test_single_pipfile(self):
        with open(f"{dir_path}/test_data/pipfile/Pipfile.lock", "r") as file:
            files = rfind_all_dependencies_files(MockLogger(), None, None, file)
            assert len(files) == 1, "Expected to find a single file"

    def test_recursive_find(self):
        logger = MockLogger()
        files = rfind_all_dependencies_files(
            logger, f"{dir_path}/test_data", None, None
        )
        assert len(files) == 11, "Expected to find eleven files"
        assert len(logger._logged) == 11, "Expected eleven debug log messages"

    def test_recursive_find_with_exclude(self):
        logger = MockLogger()
        files = rfind_all_dependencies_files(
            logger, f"{dir_path}/test_data", "fail,no_op", None
        )
        assert len(files) == 9, "Expected to find nine files"
        assert len(logger._logged) == 9, "Expected nine debug log messages"

    def test_no_files(self):
        logger = MockLogger()
        files = None
        with pytest.raises(OchronaFileException) as ex:
            files = rfind_all_dependencies_files(
                logger, f"{dir_path}/test_data/empty", None, None
            )
            assert ex == "No dependencies files found"
        assert not files

    def test_file_as_str(self):
        test_file = f"{dir_path}/test_data/fail/requirements.txt"
        files = rfind_all_dependencies_files(MockLogger(), None, None, test_file)
        assert len(files) == 1, "Expected to find a single file"


class TestFileHandlerParseToPayload:
    """
    Unit tests for file_handler:parse_to_payload method.
    """

    def test_parse_pipfile_lock(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/pipfile/Pipfile.lock"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "certifi==2019.9.11",
            "chardet==3.0.4",
            "idna==2.8",
            "requests==2.22.0",
            "urllib3==1.25.6",
        ]

    def test_parse_pipfile_lock_dev(self):
        conf = MockConfig()
        conf._include_dev = True
        test_file = f"{dir_path}/test_data/pipfile/Pipfile.lock"
        payload = parse_to_payload(
            logger=MockLogger(), file_path=test_file, config=conf
        )
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "certifi==2019.9.11",
            "chardet==3.0.4",
            "idna==2.8",
            "requests==2.22.0",
            "urllib3==1.25.6",
            "fake_package==1.13.2",
        ]

    def test_parse_poetry_lock(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/poetry/poetry.lock"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "A==1.0",
            "B==1.1",
        ]

    def test_parse_poetry_lock_dev(self):
        conf = MockConfig()
        conf._include_dev = True
        test_file = f"{dir_path}/test_data/poetry/poetry.lock"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == ["A==1.0", "B==1.1", "C==1.22.0"]

    def test_parse_setup_py(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/setup/setup.py"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "A>=1.0.0",
            "B==0.1.2",
        ]

    def test_parse_setup_py_dev(self):
        conf = MockConfig()
        conf._include_dev = True
        test_file = f"{dir_path}/test_data/setup/setup.py"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "A>=1.0.0",
            "B==0.1.2",
            "C==2.3.1",
        ]

    def test_parse_requirements_txt(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/pass/requirements.txt"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "requests==2.22.0",
            "Click==7.0",
            "Flask==1.1.1",
            "itsdangerous==1.1.0",
            "Jinja2==2.10.1",
            "MarkupSafe==1.1.1",
            "Werkzeug==0.15.4",
        ]

    def test_parse_empty_requirements_txt(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/no_op/requirements.txt"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == []

    def test_parse_conda_environment(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/conda/environment.yml"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "Flask-Testing",
            "pycryptodomex==3.8.1",
            "pytest-mpl==0.10.*",
        ]

    def test_parse_tox_direct(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/tox/direct/tox.ini"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "Django>=2.2,<2.3",
            "Django>=3.0,<3.1",
            "PyMySQL",
            "urllib3",
            "fakefakefake",
        ]

    def test_parse_tox_reference(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/tox/reference/tox.ini"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "requests=2.11.0",
        ]

    def test_parse_constraints(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/constraints/constraints.txt"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "defusedxml==0.4.1",
            "requests==2.9.1",
            "requests-oauthlib==0.6.1",
        ]

    def test_parse_direct(self):
        conf = MockConfig()
        test_input = "#comment\ndefusedxml==0.4.1\nrequests==2.9.1"
        payload = parse_direct_to_payload(MockLogger(), test_input, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "defusedxml==0.4.1",
            "requests==2.9.1",
        ]

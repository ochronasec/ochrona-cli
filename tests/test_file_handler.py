import os
import pytest
from json import loads

from ochrona.file_handler import (
    rfind_all_dependencies_files,
    parse_to_payload,
)
from ochrona.exceptions import OchronaFileException

dir_path = os.path.dirname(os.path.abspath(__file__))


class MockLogger:

    _logged = []

    def debug(self, msg):
        self._logged.append(msg)


class TestFileHandlerRfindAllDependenciesFiles:
    """
    Unit tests for file_handler:rfind_all_dependencies_files method.
    """

    def test_single_requirements(self):
        with open(f"{dir_path}/test_data/fail/requirements.txt", "r") as file:
            files = rfind_all_dependencies_files(MockLogger(), None, file)
            assert len(files) == 1, "Expected to find a single file"

    def test_single_pipfile(self):
        with open(f"{dir_path}/test_data/pipfile/Pipfile.lock", "r") as file:
            files = rfind_all_dependencies_files(MockLogger(), None, file)
            assert len(files) == 1, "Expected to find a single file"

    def test_recursive_pipfile(self):
        logger = MockLogger()
        files = rfind_all_dependencies_files(logger, f"{dir_path}/test_data", None)
        assert len(files) == 3, "Expected to find three files"
        assert len(logger._logged) == 3, "Expected three debug log messages"

    def test_no_files(self):
        logger = MockLogger()
        files = None
        with pytest.raises(OchronaFileException) as ex:
            files = rfind_all_dependencies_files(
                logger, f"{dir_path}/test_data/empty", None
            )
            assert ex == "No dependencies files found"
        assert not files


class TestFileHandlerParseToPayload:
    """
    Unit tests for file_handler:parse_to_payload method.
    """

    def test_parse_pipfile_lock(self):
        test_file = f"{dir_path}/test_data/pipfile/Pipfile.lock"
        payload = loads(parse_to_payload(MockLogger(), test_file))
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            "certifi==2019.9.11",
            "chardet==3.0.4",
            "idna==2.8",
            "requests==2.22.0",
            "urllib3==1.25.6",
        ]

    def test_parse_pipfile_lock_dev(self):
        test_file = f"{dir_path}/test_data/pipfile/Pipfile.lock"
        payload = loads(
            parse_to_payload(logger=MockLogger(), file=test_file, include_dev=True)
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

import os
import pytest
from json import loads

from ochrona.file import (
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
    _policies = []

    @property
    def include_dev(self):
        return self._include_dev

    @property
    def policies(self):
        return self._policies


class TestFileHandlerRfindAllDependenciesFiles:
    """
    Unit tests for file:rfind_all_dependencies_files method.
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
            {'version': 'certifi==2019.9.11', 'hashes': ['sha256:e4f3620cfea4f83eedc95b24abd9cd56f3c4b146dd0177e83a21b4eb49e21e50', 'sha256:fd7c7c74727ddcf00e9acd26bba8da604ffec95bf1c2144e67aff7a8b50e6cef']},
            {'version': 'chardet==3.0.4', 'hashes': ['sha256:84ab92ed1c4d4f16916e05906b6b75a6c0fb5db821cc65e70cbd64a3e2a5eaae', 'sha256:fc323ffcaeaed0e0a02bf4d117757b98aed530d9ed4531e3e15460124c106691']},
            {'version': 'idna==2.8', 'hashes': ['sha256:c357b3f628cf53ae2c4c05627ecc484553142ca23264e593d327bcde5e9c3407', 'sha256:ea8b7f6188e6fa117537c3df7da9fc686d485087abf6ac197f9c46432f7e4a3c']},
            {'version': 'requests==2.22.0', 'hashes': ['sha256:11e007a8a2aa0323f5a921e9e6a2d7e4e67d9877e85773fba9ba6419025cbeb4', 'sha256:9cf5292fcd0f598c671cfc1e0d7d1a7f13bb8085e9a590f48c010551dc6c4b31']}, {'version': 'urllib3==1.26.6', 'hashes': ['sha256:3de946ffbed6e6746608990594d08faac602528ac7015ac28d33cee6a45b7398', 'sha256:9a107b99a5393caf59c7aa3c1249c16e6879447533d0887f4336dde834c7be86']}
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
            {'version': 'certifi==2019.9.11', 'hashes': ['sha256:e4f3620cfea4f83eedc95b24abd9cd56f3c4b146dd0177e83a21b4eb49e21e50', 'sha256:fd7c7c74727ddcf00e9acd26bba8da604ffec95bf1c2144e67aff7a8b50e6cef']},
            {'version': 'chardet==3.0.4', 'hashes': ['sha256:84ab92ed1c4d4f16916e05906b6b75a6c0fb5db821cc65e70cbd64a3e2a5eaae', 'sha256:fc323ffcaeaed0e0a02bf4d117757b98aed530d9ed4531e3e15460124c106691']},
            {'version': 'idna==2.8', 'hashes': ['sha256:c357b3f628cf53ae2c4c05627ecc484553142ca23264e593d327bcde5e9c3407', 'sha256:ea8b7f6188e6fa117537c3df7da9fc686d485087abf6ac197f9c46432f7e4a3c']},
            {'version': 'requests==2.22.0', 'hashes': ['sha256:11e007a8a2aa0323f5a921e9e6a2d7e4e67d9877e85773fba9ba6419025cbeb4', 'sha256:9cf5292fcd0f598c671cfc1e0d7d1a7f13bb8085e9a590f48c010551dc6c4b31']},
            {'version': 'urllib3==1.26.6', 'hashes': ['sha256:3de946ffbed6e6746608990594d08faac602528ac7015ac28d33cee6a45b7398', 'sha256:9a107b99a5393caf59c7aa3c1249c16e6879447533d0887f4336dde834c7be86']},
            {'version': 'fake_package==1.13.2', 'hashes': ['sha256:3de946ffbed6e6746608990594d08faac602528ac7015ac28d33cee6a45b7398']}
        ]

    def test_parse_poetry_lock(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/poetry/poetry.lock"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [{'version': 'A==1.0', 'hashes': []}, {'version': 'B==1.1', 'hashes': []}]

    def test_parse_poetry_lock_dev(self):
        conf = MockConfig()
        conf._include_dev = True
        test_file = f"{dir_path}/test_data/poetry/poetry.lock"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            {'version': 'A==1.0', 'hashes': []},
            {'version': 'B==1.1', 'hashes': []},
            {'version': 'C==1.22.0', 'hashes': []}
        ]

    def test_parse_setup_py(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/setup/setup.py"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [{'version': 'A>=1.0.0', 'hashes': []}, {'version': 'B==0.1.2', 'hashes': []}]

    def test_parse_setup_py_dev(self):
        conf = MockConfig()
        conf._include_dev = True
        test_file = f"{dir_path}/test_data/setup/setup.py"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            {'version': 'A>=1.0.0', 'hashes': []},
            {'version': 'B==0.1.2', 'hashes': []},
            {'version': 'C==2.3.1', 'hashes': []}
        ]

    def test_parse_requirements_txt(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/pass/requirements.txt"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            {'hashes': [], 'version': 'requests==2.22.0'},
            {'hashes': [], 'version': 'Click==7.0'},
            {'hashes': [], 'version': 'Flask==1.1.1'},
            {'hashes': [], 'version': 'itsdangerous==1.1.0'},
            {'hashes': [], 'version': 'Jinja2==2.11.3'},
            {'hashes': [], 'version': 'MarkupSafe==1.1.1'},
            {'hashes': [], 'version': 'Werkzeug==0.15.4'}
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
            {'version': 'Flask-Testing', 'hashes': []},
            {'version': 'pycryptodomex==3.8.1', 'hashes': []},
            {'version': 'pytest-mpl==0.10.*', 'hashes': []}
        ]

    def test_parse_tox_direct(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/tox/direct/tox.ini"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            {'version': 'Django>=2.2,<2.3', 'hashes': []},
            {'version': 'Django>=3.0,<3.1', 'hashes': []},
            {'version': 'PyMySQL', 'hashes': []},
            {'version': 'urllib3', 'hashes': []},
            {'version': 'fakefakefake', 'hashes': []}
        ]

    def test_parse_tox_reference(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/tox/reference/tox.ini"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            {'version': "requests=2.11.0", 'hashes': []}
        ]

    def test_parse_constraints(self):
        conf = MockConfig()
        test_file = f"{dir_path}/test_data/constraints/constraints.txt"
        payload = parse_to_payload(MockLogger(), test_file, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            {'version': "defusedxml==0.4.1", 'hashes': []},
            {'version': "requests==2.9.1", 'hashes': []},
            {'version': "requests-oauthlib==0.6.1", 'hashes': []}
        ]

    def test_parse_direct(self):
        conf = MockConfig()
        test_input = "#comment\ndefusedxml==0.4.1\nrequests==2.9.1"
        payload = parse_direct_to_payload(MockLogger(), test_input, config=conf)
        assert "dependencies" in payload
        assert payload["dependencies"] == [
            {'version': "defusedxml==0.4.1", 'hashes': []},
            {'version': "requests==2.9.1", 'hashes': []}
        ]

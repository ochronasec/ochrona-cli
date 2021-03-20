import os
from unittest import mock

import pytest

from ochrona.import_wrapper import SafeImport
from ochrona.exceptions import OchronaImportException


class MockLogger:
    def __init__(self):
        self._info = []
        self._warn = []
        self._error = []

    def info(self, msg):
        self._info.append(msg)

    def warn(self, msg):
        self._warn.append(msg)

    def error(self, msg):
        self._error.append(msg)


class MockClient:

    _analyzed = []
    _response = {}

    def __init__(self, response):
        self._response = response
        self._analyzed = []

    def analyze(self, payload):
        self._analyzed.append(payload)
        return self._response


class TestImportWrapper:
    """
    Component tests for import_wrapper module.
    """

    @mock.patch("ochrona.import_wrapper.SafeImport._get_most_recent_version")
    @mock.patch("ochrona.import_wrapper.SafeImport._install")
    def test_install(self, install, most_recent):
        install.return_value = True
        logger = MockLogger()
        client = MockClient(
            {
                "flat_list": ["A==1.2.3"],
                "confirmed_vulnerabilities": [],
            }
        )
        importer = SafeImport(logger, client)
        importer.install("A==1.2.3")

        install.assert_called_once()
        most_recent.assert_not_called()
        assert len(client._analyzed) == 1
        assert client._analyzed[0] == '{"dependencies": ["A==1.2.3"]}'
        assert (
            logger._info[0]
            == "A full list of packages to be installed, included dependencies: A==1.2.3"
        )

    @mock.patch("ochrona.import_wrapper.SafeImport._get_most_recent_version")
    @mock.patch("ochrona.import_wrapper.SafeImport._install")
    def test_install_missing_version(self, install, most_recent):
        install.return_value = True
        most_recent.return_value = "A==1.2.3"
        logger = MockLogger()
        client = MockClient(
            {
                "flat_list": ["A==1.2.3"],
                "confirmed_vulnerabilities": [],
            }
        )
        importer = SafeImport(logger, client)
        importer.install("A")

        install.assert_called_once()
        most_recent.assert_called_once()
        assert len(client._analyzed) == 1
        assert client._analyzed[0] == '{"dependencies": ["A==1.2.3"]}'
        assert (
            logger._info[0]
            == "A full list of packages to be installed, included dependencies: A==1.2.3"
        )

    @mock.patch("ochrona.import_wrapper.SafeImport._get_most_recent_version")
    @mock.patch("ochrona.import_wrapper.SafeImport._install")
    def test_install_confirmed_vuln(self, install, most_recent):
        install.return_value = True
        most_recent.return_value = "A==1.2.3"
        logger = MockLogger()
        client = MockClient(
            {
                "flat_list": ["A==1.2.3"],
                "confirmed_vulnerabilities": [
                    {
                        "name": "A",
                        "cve_id": "FAKE-123",
                        "description": "A fake vulnerability",
                        "ochrona_severity_score": 5.0,
                    }
                ],
            }
        )
        importer = SafeImport(logger, client)
        importer.install("A")

        install.assert_not_called()
        most_recent.assert_called_once()
        assert len(client._analyzed) == 1
        assert client._analyzed[0] == '{"dependencies": ["A==1.2.3"]}'
        assert len(logger._error) == 2
        assert (
            logger._error[-1] == "Import of A aborted due to detected vulnerabilities."
        )

    def test_install_invalid_specifier(self):
        logger = MockLogger()
        client = MockClient({})
        importer = SafeImport(logger, client)
        with pytest.raises(OchronaImportException) as ex:
            importer.install("A>=1.0.0")
            assert (
                "An invalid specifier was found in A, either specify the package without a version or pin to a single version using `name==version`."
                in ex
            )

    @mock.patch("ochrona.import_wrapper.SafeImport._install")
    @mock.patch("ochrona.import_wrapper.SafeImport._install_file")
    def test_install_file(self, install_file, install):
        install_file.return_value = True
        logger = MockLogger()
        client = MockClient(
            {
                "flat_list": [
                    "requests==2.22.0",
                    "Click==7.0",
                    "Flask==1.1.1",
                    "itsdangerous==1.1.0",
                    "Jinja2==2.11.3",
                    "MarkupSafe==1.1.1",
                    "Werkzeug==0.15.4",
                ],
                "confirmed_vulnerabilities": [],
            }
        )
        importer = SafeImport(logger, client)
        importer.install("./tests/test_data/pass/requirements.txt")

        install_file.assert_called_once()
        install.assert_not_called()
        assert len(client._analyzed) == 1
        assert (
            client._analyzed[0]
            == '{"dependencies": ["requests==2.22.0", "Click==7.0", "Flask==1.1.1", "itsdangerous==1.1.0", "Jinja2==2.10.1", "MarkupSafe==1.1.1", "Werkzeug==0.15.4"]}'
        )
        assert (
            logger._info[0]
            == "A full list of packages to be installed, included dependencies: requests==2.22.0, Click==7.0, Flask==1.1.1, itsdangerous==1.1.0, Jinja2==2.10.1, MarkupSafe==1.1.1, Werkzeug==0.15.4"
        )

    @mock.patch("ochrona.import_wrapper.SafeImport._install")
    @mock.patch("ochrona.import_wrapper.SafeImport._install_file")
    def test_install_file_fail(self, install_file, install):
        install_file.return_value = True
        logger = MockLogger()
        client = MockClient(
            {
                "flat_list": [
                    "requests==2.19.0",
                    "Click==7.0",
                    "Flask==1.1.1",
                    "itsdangerous==1.1.0",
                    "Jinja2==2.10.1",
                    "MarkupSafe==1.1.1",
                    "Werkzeug==0.15.4",
                ],
                "confirmed_vulnerabilities": [
                    {
                        "name": "requests",
                        "cve_id": "FAKE-123",
                        "description": "A fake vulnerability",
                        "ochrona_severity_score": 5.0,
                    }
                ],
            }
        )
        importer = SafeImport(logger, client)
        importer.install("./tests/test_data/fail/requirements.txt")

        install_file.assert_not_called()
        install.assert_not_called()
        assert len(client._analyzed) == 1
        assert (
            client._analyzed[0]
            == '{"dependencies": ["requests==2.19.0", "Click==7.0", "Flask==1.1.1", "itsdangerous==1.1.0", "Jinja2==2.10.1", "MarkupSafe==1.1.1", "Werkzeug==0.15.4"]}'
        )
        assert (
            logger._info[0]
            == "A full list of packages that would be installed, included dependencies: requests==2.19.0, Click==7.0, Flask==1.1.1, itsdangerous==1.1.0, Jinja2==2.10.1, MarkupSafe==1.1.1, Werkzeug==0.15.4"
        )

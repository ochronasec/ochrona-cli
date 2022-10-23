import os
from unittest import mock

import pytest

from ochrona.importer import SafeImport
from ochrona.exceptions import OchronaImportException


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


class TestImportWrapper:
    """
    Component tests for importer module.
    """

    @mock.patch("ochrona.importer.SafeImport._get_most_recent_version")
    @mock.patch("ochrona.importer.SafeImport._install")
    def test_install(self, install, most_recent):
        install.return_value = True
        logger = MockLogger()
        config = MockConfig()
        importer = SafeImport(logger, config)
        importer.install("A==1.2.3")

        install.assert_called_once()
        most_recent.assert_not_called()
        assert (
            logger._info[0]
            == f"A full list of packages to be installed, included dependencies: {os.linesep}A==1.2.3"
        )

    @mock.patch("ochrona.importer.SafeImport._get_most_recent_version")
    @mock.patch("ochrona.importer.SafeImport._install")
    def test_install_missing_version(self, install, most_recent):
        install.return_value = True
        most_recent.return_value = "A==1.2.3"
        logger = MockLogger()
        config = MockConfig()
        importer = SafeImport(logger, config)
        importer.install("A")

        install.assert_called_once()
        most_recent.assert_called_once()
        assert (
            logger._info[0]
            == f"A full list of packages to be installed, included dependencies: {os.linesep}A==1.2.3"
        )

    @mock.patch("ochrona.importer.SafeImport._get_most_recent_version")
    @mock.patch("ochrona.importer.SafeImport._install")
    def test_install_confirmed_vuln(self, install, most_recent):
        install.return_value = True
        most_recent.return_value = "urllib3==1.25.6"
        logger = MockLogger()
        config = MockConfig()
        importer = SafeImport(logger, config)
        importer.install("urllib3")

        install.assert_not_called()
        most_recent.assert_called_once()
        assert len(logger._error) == 2
        assert (
            logger._error[-1]
            == "Import of [bold]urllib3[/bold] aborted due to detected vulnerabilities."
        )

    def test_install_invalid_specifier(self):
        logger = MockLogger()
        config = MockConfig()
        importer = SafeImport(logger, config)
        with pytest.raises(OchronaImportException) as ex:
            importer.install("A>=1.0.0")
            assert (
                "An invalid specifier was found in A, either specify the package without a version or pin to a single version using `name==version`."
                in ex
            )

    @mock.patch("ochrona.importer.SafeImport._install")
    @mock.patch("ochrona.importer.SafeImport._install_file")
    def test_install_file(self, install_file, install):
        install_file.return_value = True
        logger = MockLogger()
        config = MockConfig()
        importer = SafeImport(logger, config)
        importer.install("./tests/test_data/pass/requirements.txt")

        install_file.assert_called_once()
        install.assert_not_called()
        included_dependencies = [
            "Click==7.0",
            "itsdangerous==1.1.0",
            "MarkupSafe==1.1.1",
            "Werkzeug==0.15.4",
            "requests==2.22.0",
            "Jinja2==2.11.3",
            "Flask==1.1.1",
        ]
        for dep in included_dependencies:
            assert dep in logger._info[0]
        assert logger._info[0].startswith(
            "A full list of packages to be installed, included dependencies:"
        )

    @mock.patch("ochrona.importer.SafeImport._install")
    @mock.patch("ochrona.importer.SafeImport._install_file")
    def test_install_file_fail(self, install_file, install):
        install_file.return_value = True
        logger = MockLogger()
        config = MockConfig()
        importer = SafeImport(logger, config)
        importer.install("./tests/test_data/fail/requirements.txt")

        install_file.assert_not_called()
        install.assert_not_called()
        included_dependencies = [
            "Click==7.0",
            "itsdangerous==1.1.0",
            "MarkupSafe==1.1.1",
            "Werkzeug==0.15.4",
            "requests==2.19.0",
            "Jinja2==2.10.1",
            "Flask==1.1.1",
        ]
        for dep in included_dependencies:
            assert dep in logger._info[0]
        assert logger._info[0].startswith(
            "A full list of packages that would be installed, included dependencies:"
        )

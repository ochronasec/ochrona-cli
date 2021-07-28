import os
import pytest
from unittest import mock
from json import loads

from ochrona.db import VulnDB

dir_path = os.path.dirname(os.path.abspath(__file__))


class MockLogger:
    def __init__(self):
        self._logged = []

    def debug(self, msg):
        self._logged.append(msg)

class TestVulnDB:
    """
    Unit tests for db:VulnDB
    """
    @mock.patch("ochrona.db.db.VulnDB.user_app_dir", new_callable=mock.PropertyMock)
    @mock.patch("ochrona.db.db.VulnDB._download_latest_db")
    def test_no_existing_db(self, download ,appdir):
        appdir.return_value = dir_path + "/test_data/db_missing"
        logger = MockLogger()
        db = VulnDB(logger)
        download.assert_called_once()

    @mock.patch("ochrona.db.db.VulnDB.user_app_dir", new_callable=mock.PropertyMock)
    @mock.patch("ochrona.db.db.VulnDB._is_update_available")
    @mock.patch("ochrona.db.db.VulnDB._download_latest_db")
    def test_db_exists_no_update(self, download , update, appdir):
        appdir.return_value = dir_path + "/test_data/db_present"
        update.return_value = False
        logger = MockLogger()
        db = VulnDB(logger)
        download.assert_not_called()

    @mock.patch("ochrona.db.db.VulnDB.user_app_dir", new_callable=mock.PropertyMock)
    @mock.patch("ochrona.db.db.VulnDB._is_update_available")
    @mock.patch("ochrona.db.db.VulnDB._delete_old_dbs")
    @mock.patch("ochrona.db.db.VulnDB._download_latest_db")
    def test_db_exists_update_available(self, download, delete, update, appdir):
        appdir.return_value = dir_path + "/test_data/db_present"
        update.return_value = True
        logger = MockLogger()
        db = VulnDB(logger)
        delete.assert_called_once()
        download.assert_called_once()

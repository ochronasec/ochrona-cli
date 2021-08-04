import datetime
import glob
import json
import os
import pathlib
import re
from typing import Any, Dict, List, Optional

from appdirs import AppDirs  # type: ignore
import requests
import requests_cache  # type: ignore
from tarsafe import TarSafe  # type: ignore

from ochrona.log import OchronaLogger

# Cache settings
expire_after = datetime.timedelta(hours=1)
requests_cache.install_cache("db_cache", expire_after=expire_after)

RELEASES_URL = (
    "https://api.github.com/repos/ochronasec/ochrona_python_vulnerabilities/releases"
)
VULN_PATTERN = "\.\/vulns\/({})[\-A-Z\-0-9]*\.json"


class VulnDB:

    latest_version: Optional[str] = None
    latest_db_path: Optional[str] = None
    _user_app_dir: str = AppDirs("Ochrona", "Ochrona").user_data_dir

    def __init__(self, logger: OchronaLogger):
        self._logger = logger
        self._create_user_app_dir()
        self._check_local_db_present()
        if self.latest_version is not None:
            if self._is_update_available():
                self._logger.debug(f"More recent version of DB found, will update")
                self._update_db()
        else:
            self._download_latest_db()

    def _is_update_available(self):
        try:
            releases = requests.get(RELEASES_URL).json()
            top_version = max([r.get("name") for r in releases])
            return top_version > self.latest_version
        except Exception as ex:
            self._logger.error(f"Error fetching new releases: {ex}")
            return False

    def _check_local_db_present(self):
        files = glob.glob(f"{self.user_app_dir}/*tar.gz")
        if len(files) > 0:
            version = pathlib.Path(files[0]).name.replace(".tar.gz", "")
            self.latest_version = version
            self.latest_db_path = f"{self.user_app_dir}/{self.latest_version}.tar.gz"
            self._logger.debug(f"DB instance found: {version}")

    def _download_latest_db(self):
        releases = requests.get(RELEASES_URL).json()
        sorted_releases = sorted(releases, key=lambda r: r["name"], reverse=True)
        r = requests.get(
            sorted_releases[0].get("assets")[0].get("browser_download_url")
        )
        with open(
            f"{self.user_app_dir}/{sorted_releases[0].get('assets')[0].get('name')}",
            "wb",
        ) as f:
            f.write(r.content)
        self.latest_version = (
            sorted_releases[0].get("assets")[0].get("name").replace(".tar.gz", "")
        )
        self.latest_db_path = f"{self.user_app_dir}/{self.latest_version}.tar.gz"
        self._logger.debug(f"DB upgraded to {self.latest_version}")

    def _create_user_app_dir(self):
        os.makedirs(self.user_app_dir, exist_ok=True)

    def _update_db(self):
        self._delete_old_dbs()
        self._download_latest_db()

    def _delete_old_dbs(self):
        files = glob.glob(f"{self.user_app_dir}/*tar.gz")
        for file_ in files:
            os.remove(file_)

    def lookup_by_name(self, name: str) -> List[Dict[str, Any]]:
        potential_vuln_paths = []
        potential_vulns = []
        with TarSafe.open(self.latest_db_path, "r:gz") as tar:
            vulns = tar.getmembers()
            for vuln in vulns:
                if re.match(VULN_PATTERN.format(name), vuln.name):
                    potential_vuln_paths.append(vuln.name)

            for vuln_path in potential_vuln_paths:
                potential_vulns.append(json.loads(tar.extractfile(vuln_path).read()))
        self._logger.debug(
            f"Found {len(potential_vulns)} vulnerabilities potentially affecting package: {name}"
        )
        return potential_vulns

    @property
    def user_app_dir(self):
        return self._user_app_dir

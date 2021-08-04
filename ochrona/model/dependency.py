import dateutil.parser
import re

from packaging.specifiers import Version
from packaging.version import parse
from typing import Any, Dict, Tuple

from ochrona.client import pypi_fetch
from ochrona.const import LICENSE_MAP

PEP_SUPPORTED_OPERATORS = r"==|>=|<=|!=|~=|<|>"


class Dependency:
    """
    A python dependency object.
    """

    _raw: str = ""
    _name: str = ""
    _version: str = ""
    _version_major: str = ""
    _version_minor: str = ""
    _version_release: str = ""
    _operator: str = ""
    _full: str = ""
    _latest_version: str = ""
    _license_type: str = ""
    _latest_update: str = ""
    _release_count: str = ""
    _is_reference: bool = False

    def __init__(self, dependency: str):
        self._raw = dependency.split(",")[0]
        parts = re.split(PEP_SUPPORTED_OPERATORS, self._raw)
        if len(parts) == 1:
            if "txt" in parts[0] and "-r" in parts[0]:
                self.is_reference = True
                return
            self._name = parts[0]
        elif len(parts) > 1:
            self._name = parts[0]
            self._parse_version(parts[1])
            self._operator = re.sub("[a-zA-Z0-9.-]", "", self._raw)  # TODO fix
        (
            self._latest_version,
            self._license_type,
            self._latest_update,
            self._release_count,
        ) = self._pypi_details()
        self._full = self._provided_or_most_recent() or self._raw

    def _parse_version(self, version: str):
        v = Version(version)
        self._version = v.base_version
        version_parts = v.release
        if len(version_parts) == 1:
            self._version_major = str(version_parts[0])
        elif len(version_parts) == 2:
            self._version_major = str(version_parts[0])
            self._version_minor = str(version_parts[1])
        else:
            self._version_major = str(version_parts[0])
            self._version_minor = str(version_parts[1])
            self._version_release = str(version_parts[2])

    def _pypi_details(self) -> Tuple[str, str, str, str]:
        """
        Calls to pypi to resolve transitive dependencies.
        """
        json_value = pypi_fetch(self._name)
        if json_value:
            latest_version = self._parse_latest_version(json_value)
            license_value = self._get_license(json_value)
            latest_release_date = self._parse_latest_update(json_value, latest_version)
            release_count = self._parse_release_count(json_value)
            return latest_version, license_value, latest_release_date, release_count
        return "", "Unknown", "", ""

    def to_json(self) -> Dict[str, Any]:
        """
        Returns PythonDependency as a dict so it can be json deserialized.
        """
        return self.__dict__

    def _parse_latest_version(self, resp: Dict[str, Any]) -> str:
        version = resp.get("info", {}).get("version")
        if version is not None:
            return version
        # Fallback and check releases
        releases = resp.get("releases", {})
        if len(releases) > 1:
            return list(releases.keys())[-1]
        return ""

    def _parse_latest_update(self, resp: Dict[str, Any], latest_version: str) -> str:
        """
        Return when the latest version was published
        """
        latest_release = resp.get("releases", {}).get(latest_version)
        if latest_release is not None and isinstance(latest_release, list):
            release_artifact_dates = []
            for artifact in latest_release:
                try:
                    upload_time = artifact.get("upload_time_iso_8601")
                    parsed_upload_time = dateutil.parser.isoparse(upload_time)
                    release_artifact_dates.append(parsed_upload_time)
                except Exception:
                    pass
            latest_artifact_timestamp = max(release_artifact_dates)
            return latest_artifact_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        return ""

    def _parse_release_count(self, resp: Dict[str, Any]) -> str:
        """
        Returns the total number of releases
        """
        return f"{len(resp.get('releases', []))}"

    def _get_license(self, resp: Dict[str, Any]) -> str:
        raw_license = resp.get("info", {}).get("license", None)
        if raw_license is not None:
            for ltype, matches in LICENSE_MAP.items():
                if raw_license in matches:
                    return ltype
            return raw_license
        return "Unknown"

    def _provided_or_most_recent(self) -> str:
        """
        During resolution we should decide if the provided dependency, or the
        most recent version of the dependency should be returned.

        ex.
            Required if pkg>=1.0.1
            Current version is pkg==1.2.4
            We should return pkg==1.2.4
        """
        if self._operator == ">=" and parse(self._version) <= parse(
            self._latest_version
        ):
            return f"{self._name}=={self._latest_version}"
        elif (
            self._operator == "" and self._version == "" and self._latest_version != ""
        ):
            return f"{self._name}=={self._latest_version}"
        return self._raw

    @property
    def full(self) -> str:
        return self._full

    @property
    def license_type(self) -> str:
        return self._license_type

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

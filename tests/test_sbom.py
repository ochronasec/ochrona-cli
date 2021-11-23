import json
import os
import pytest
import xml.etree.ElementTree as ET

import ochrona.eval.eval as e
from ochrona.sbom.specs.cyclonedx import CycloneDX

dir_path = os.path.dirname(os.path.abspath(__file__))


class MockLogger:
    def __init__(self):
        self._debug = []

    def debug(self, msg):
        self._debug.append(msg)

class TestSBOMCycloneDX:
    """
    Unit tests for sbom:CycloneDX:json
    """

    def test_cyclonedx_json(self):
        res = e.resolve(dependencies=[{"version": "requests==2.22.0", "hashes": ["sha256:11e007a8a2aa0323f5a921e9e6a2d7e4e67d9877e85773fba9ba6419025cbeb4", "sha256:9cf5292fcd0f598c671cfc1e0d7d1a7f13bb8085e9a590f48c010551dc6c4b31"]}], logger=MockLogger())
        cyclone = CycloneDX(dependency_set=res)
        cyclone.json(f"{dir_path}/test_data/output")

        with open(f"{dir_path}/test_data/output/bom.json") as f:
            j = json.load(f)
            assert j.get("bomFormat") == "CycloneDX"
            assert len(j.get("components")) == 1
            assert j.get("components")[0].get("name") == "requests"
            assert len(j.get("components")[0].get("hashes")) == 2
            assert j.get("components")[0].get("licenses")[0].get("license").get("id") == "Apache-2.0"
        os.remove(f"{dir_path}/test_data/output/bom.json")

    def test_cyclonedx_xml(self):
        res = e.resolve(dependencies=[{"version": "requests==2.22.0", "hashes": ["sha256:11e007a8a2aa0323f5a921e9e6a2d7e4e67d9877e85773fba9ba6419025cbeb4", "sha256:9cf5292fcd0f598c671cfc1e0d7d1a7f13bb8085e9a590f48c010551dc6c4b31"]}], logger=MockLogger())
        cyclone = CycloneDX(dependency_set=res)
        cyclone.xml(f"{dir_path}/test_data/output")

        tree = ET.parse(f"{dir_path}/test_data/output/bom.xml")
        root = tree.getroot()
        assert root.attrib.get("version") == "1"
        assert root[1][0][0].text == "requests"
        assert root[1][0][3][0].text == "11e007a8a2aa0323f5a921e9e6a2d7e4e67d9877e85773fba9ba6419025cbeb4"
        assert root[1][0][4][0][0].text == "Apache-2.0"
        os.remove(f"{dir_path}/test_data/output/bom.xml")

from datetime import datetime
import json
import uuid
import xml.etree.ElementTree as ET
from xml.dom import minidom

from ochrona import __version__ as version


class CycloneDX:
    """
    Based on Spec 1.3
    https://cyclonedx.org/docs/1.3/json/
    """

    def __init__(self, dependency_set):
        self._dependencies = dependency_set.dependencies

    def json(self, location: str):
        """
        Writes CycloneDX Json to location
        """

        base = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "version": 1,
        }

        # Metadata
        base["metadata"] = {
            "timestamp": datetime.now().isoformat(),
            "tools": [{"vendor": "Ochrona", "name": "Ochrona", "version": version}],
        }

        # Serial
        base["serialNumber"] = f"urn:uuid{uuid.uuid4()}"

        # Components
        base["components"] = []
        for dep in self._dependencies:
            entry = {
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "purl": dep.purl,
                "hashes": [],
                "licenses": [{"license": {"id": dep.license_type}}],
            }
            for alg, hashes in dep.hashes.items():
                for hash_entry in hashes:
                    entry["hashes"].append({"alg": alg.upper(), "content": hash_entry})
            base["components"].append(entry)  # type: ignore[attr-defined]

        with open(f"{location}/bom.json", "w") as f:
            f.write(json.dumps(base))

    def xml(self, location: str):
        """
        Writes CycloneDX XML to location
        """
        bom = ET.Element("bom")
        bom.set("version", "1")
        bom.set("serialNumber", f"urn:uuid{uuid.uuid4()}")
        bom.set("xmlns", "http://cyclonedx.org/schema/bom/1.3")
        meta = ET.SubElement(bom, "metadata")
        ts = ET.SubElement(meta, "timestamp")
        ts.text = datetime.now().isoformat()
        tools = ET.SubElement(meta, "tools")
        tool = ET.SubElement(tools, "tool")
        vendor = ET.SubElement(tool, "vendor")
        vendor.text = "Ochrona"
        tname = ET.SubElement(tool, "name")
        tname.text = "Ochrona"
        tversion = ET.SubElement(tool, "version")
        tversion.text = version
        components = ET.SubElement(bom, "components")
        for dep in self._dependencies:
            component = ET.SubElement(components, "component")
            component.set("type", "library")
            name = ET.SubElement(component, "name")
            name.text = dep.name
            cversion = ET.SubElement(component, "version")
            cversion.text = dep.version
            purl = ET.SubElement(component, "purl")
            purl.text = dep.purl
            hashes_list = ET.SubElement(component, "hashes")
            for alg, hashes in dep.hashes.items():
                for hash_entry in hashes:
                    h = ET.SubElement(hashes_list, "hash")
                    h.set("alg", alg.upper())
                    h.text = hash_entry
            licenses = ET.SubElement(component, "licenses")
            lic = ET.SubElement(licenses, "license")
            lid = ET.SubElement(lic, "id")
            lid.text = dep.license_type

        with open(f"{location}/bom.xml", "w") as f:
            f.write(minidom.parseString(ET.tostring(bom)).toprettyxml(indent="   "))

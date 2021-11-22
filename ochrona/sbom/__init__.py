from typing import Dict, List, Union

from ochrona.exceptions import OchronaException
from ochrona.model.dependency import Dependency
from ochrona.model.dependency_set import DependencySet
from ochrona.sbom.specs.cyclonedx import CycloneDX


def generate_sbom(
    dependencies: List[Dict[str, Union[str, List[str]]]], location: str, format: str
):
    """
    Will generate and output a new SBOM spec file.
    """
    # Will add additional SBOM specs in the future
    dependency_set = DependencySet([Dependency(dep) for dep in dependencies])
    spec = CycloneDX(dependency_set=dependency_set)

    if format == "XML":
        spec.xml(location=location)
    elif format == "JSON":
        spec.json(location=location)
    else:
        raise OchronaException(f"Unsupported SBOM format provided: {format}")

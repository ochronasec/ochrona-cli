import pytest
from unittest import mock

from ochrona.model.dependency import Dependency
from ochrona.model.dependency_set import DependencySet

class TestDependencySet:

    @mock.patch("ochrona.client.pypi_fetch")
    def test_flatten_list(self, fetch):
            dependency1 = Dependency("requests==2.18.1")
            dependency2 = Dependency("urllib3==1.26.3")
            dependency_set = DependencySet([dependency1, dependency2])
            assert len(dependency_set.flat_list) == 2

    @mock.patch("ochrona.client.pypi_fetch")
    def test_flatten_list_duplicate(self, fetch):
            dependency1 = Dependency("requests==2.18.1")
            dependency2 = Dependency("requests==2.19.2")
            dependency_set = DependencySet([dependency1, dependency2])
            assert len(dependency_set.flat_list) == 1
            assert dependency_set.flat_list[0] == "requests==2.19.2"

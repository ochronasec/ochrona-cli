import pytest
from unittest import mock

from ochrona.model.dependency import Dependency
from ochrona.model.dependency_set import DependencySet

class TestDependencySet:

    @mock.patch("ochrona.model.dependency.pypi_fetch")
    def test_flatten_list(self, fetch):
        dependency1 = Dependency({"version": "requests==2.18.1"})
        dependency2 = Dependency({"version": "urllib3==1.26.3"})
        dependency_set = DependencySet([dependency1, dependency2])
        assert len(dependency_set.flat_list) == 2

    @mock.patch("ochrona.model.dependency.pypi_fetch")
    def test_flatten_list_duplicate(self, fetch):
        dependency1 = Dependency({"version": "requests==2.18.1"})
        dependency2 = Dependency({"version": "requests==2.19.2"})
        dependency_set = DependencySet([dependency1, dependency2])
        assert len(dependency_set.flat_list) == 1
        assert dependency_set.flat_list[0] == "requests==2.19.2"

    @mock.patch("ochrona.model.dependency.pypi_fetch")
    def test_flatten_list_no_version(self, fetch):
        fetch.return_value = {"info": {"version": "2.26.1"}}
        dependency1 = Dependency({"version": "requests"})
        dependency_set = DependencySet([dependency1])
        assert len(dependency_set.flat_list) == 1
        assert dependency_set.flat_list[0] == "requests==2.26.1"

    @mock.patch("ochrona.model.dependency.pypi_fetch")
    def test_flatten_list_invalid_package_version(self, fetch):
        dependency1 = Dependency({"version": "package.fake=='2.4'"})
        dependency_set = DependencySet([dependency1])
        assert len(dependency_set.flat_list) == 1
        assert dependency_set.flat_list[0] == "package.fake==2.4"

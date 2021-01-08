#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from setuptools import setup
from ochrona import __version__ as version


try:
    with open("README.md", encoding="utf8") as readme_file:
        readme = readme_file.read()
except TypeError:
    with open("README.md") as readme_file:
        readme = readme_file.read()

requirements = ["click>=7.1.2", "pyyaml>=5.3.1", "requests>=2.25.0", "toml>=0.10.2"]

test_requirements = ["pytest>=6.1.2", "pytest-vcr>=1.0.2"]

setup(
    name="ochrona",
    version=version,
    description="Ochrona checks your open source dependencies for vulnerabilities ",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Ochrona Security",
    author_email="andrew@ochrona.dev",
    url="https://github.com/ochorna/ochrona-cli",
    packages=["ochrona","ochrona.parsers"],
    package_dir={"ochrona": "ochrona"},
    entry_points={"console_scripts": ["ochrona=ochrona.cli:run"]},
    python_requires=">=3.6",
    include_package_data=True,
    install_requires=requirements,
    license="MIT license",
    zip_safe=False,
    keywords="ochrona, security, dependencies, vulnerability, testing",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    test_suite="tests",
    tests_require=test_requirements,
)

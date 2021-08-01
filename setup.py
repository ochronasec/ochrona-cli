#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from setuptools import setup
from ochrona import __author__ as author
from ochrona import __email__ as email
from ochrona import __license__ as license_
from ochrona import __version__ as version


try:
    with open("README.md", encoding="utf8") as readme_file:
        readme = readme_file.read()
except TypeError:
    with open("README.md") as readme_file:
        readme = readme_file.read()

requirements = [
    "click>=7.1.2",
    "pyyaml>=5.4.1",
    "requests>=2.25.0",
    "toml>=0.10.2",
    "python-dateutil>=2.8.1",
    "tarsafe>=0.0.3",
    "packaging>=20.4",
    "requests-cache>=0.5.2",
    "appdirs>=1.4.4",
]

test_requirements = ["pytest>=6.1.2"]

setup(
    name="ochrona",
    version=version,
    description="Ochrona checks your open source dependencies for vulnerabilities and policy violations.",
    long_description=readme,
    long_description_content_type="text/markdown",
    author=author,
    author_email=email,
    url="https://github.com/ochronasec/ochrona-cli",
    packages=[
        "ochrona",
        "ochrona.cli",
        "ochrona.client",
        "ochrona.config",
        "ochrona.db",
        "ochrona.eval",
        "ochrona.eval.policy",
        "ochrona.eval.vuln",
        "ochrona.file",
        "ochrona.importer",
        "ochrona.log",
        "ochrona.model",
        "ochrona.parser",
        "ochrona.reporter",
        "ochrona.utils",
    ],
    package_dir={"ochrona": "ochrona"},
    entry_points={"console_scripts": ["ochrona=ochrona.cli:run"]},
    python_requires=">=3.7",
    include_package_data=True,
    install_requires=requirements,
    license=license_,
    zip_safe=False,
    keywords="ochrona, security, dependencies, vulnerability, testing, sca",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Utilities",
        "Topic :: Security",
        "Typing :: Typed",
    ],
    test_suite="tests",
    tests_require=test_requirements,
)

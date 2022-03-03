[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_logo.png" width="500"/></p>](https://ochrona.dev)

[![Ochrona](https://img.shields.io/badge/secured_by-ochrona-blue?style=flat-square)](https://ochrona.dev)
[![PyPI](https://img.shields.io/pypi/v/ochrona?color=blue&style=flat-square)](https://pypi.org/project/ochrona/)
[![Versions](https://img.shields.io/pypi/pyversions/ochrona?color=blue&logo=python&logoColor=white&style=flat-square)](https://pypi.org/project/ochrona/)
[![License](https://img.shields.io/pypi/l/ochrona?color=blue&label=License&style=flat-square)](https://pypi.org/project/ochrona/)
[![Downloads](https://img.shields.io/pypi/dm/ochrona?color=blue&label=Downloads&style=flat-square)](https://pypi.org/project/ochrona/)
[![Vuln DB Version](https://img.shields.io/github/v/release/ochronasec/ochrona_python_vulnerabilities.svg?style=flat-square&label=database)](https://github.com/ochronasec/ochrona_python_vulnerabilities)
[![codecov](https://img.shields.io/codecov/c/github/ochronasec/ochrona-cli?color=blue&style=flat-square)](https://codecov.io/gh/ochronasec/ochrona-cli)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)

- [Overview](#overview)
    + [Vulnerability Data](#vulnerability-data)
    + [Supported file types](#supported-file-types)
- [Installation](#installation)
    + [via pip](#via-pip)
    + [via pipenv](#via-pipenv)
    + [via poetry](#via-poetry)
- [Configuration](#configuration)
    + [via command line args](#via-command-line-args)
    + [via environment variables](#via-environment-variables)
    + [via .ochrona.yml](#via-ochronayml)
- [Policies](#policies)
    + [Policy Syntax](#policy-syntax)
      - [Allowed Fields](#allowed-fields)
      - [Allowed Conditional Operators](#allowed-conditional-operators)
      - [Allowed Logical Operators](#allowed-logical-operators)
      - [Special Values](#special-values)
      - [Policy Examples](#policy-examples)
- [SBOM](#sbom)
- [Static Analysis Beta](#static-analysis-beta)
    + [SAST Checks](#sast-checks)
- [Usage Examples](#usage-examples)
    + [Default Mode](#default-mode)
    + [Standard error code with Junit XML reporting saved to file](#standard-error-code-with-junit-xml-reporting-saved-to-file)
    + [Safe Import Mode](#safe-import-mode)
    + [stdin Support](#stdin-support)
      - [Single dependency via stdin](#single-dependency-via-stdin)
      - [Multi-dependency via stdin](#multi-dependency-via-stdin)
    + [Docker Support](#docker-support)
      - [Dockerized Ochrona](#dockerized-ochrona)
      - [Dockerized Ochrona with environment variables](#dockerized-ochrona-with-environment-variables)
- [Output Formats](#output-formats)
    + [Basic](#basic)
    + [Full](#full)
    + [XML (Junit)](#xml--junit-)
    + [JSON](#json)
- [Represent!](#represent-)

# Overview
Ochrona is a free solution for securing the dependencies used in Python projects. Ochrona also includes support for _policies_ which give you additional control over what aspects of your dependency usage you'd like to be alerted on.

The Ochrona maintainers care deeply about Developer Experience (DX), if you have any feedback or run into issues please open an issue [here](https://github.com/ochronasec/ochrona-cli/issues).

### Vulnerability Data
Ochrona maintains its own database of vulnerabilities impacting Python packages. You're welcome to check out the database [here](https://github.com/ochronasec/ochrona_python_vulnerabilities). This database is updated frequently using data from NVD, Github, and other sources. Ochrona will update its local copy of the database if a new version exists.

### Supported file types
- `*requirements*.txt`
- `Pipfile.lock`
- `poetry.lock`
- `setup.py`
- `*constraints*.txt`
- `environment.yml`
- `tox.ini`

# Installation

### via pip
```
pip install ochrona
```

### via pipenv
```
pipenv install --dev ochrona
```

### via poetry
```
poetry add -D ochrona
```

# Configuration
### via command line args
| Arg              | Description                                                               | Type | Example                                                                    |
|------------------|---------------------------------------------------------------------------|------|----------------------------------------------------------------------|
| `--dir`          | Directory to recursively search for dependencies files to scan [.]        | path | /User/me/my_project                                                        |
| `--exclude_dir`  | Directory names that should be excluded from recursive search. Comma separated   | str | build,dev                                                    |
| `--file`         | Single dependency file to scan                                            | file | /User/me/my_project/requirements.txt                                       |
| `--debug`        | Enable debug logging [False]                                              | bool | True                                                                       |
| `--silent`       | Silent mode [False]                                                       | bool | True                                                                       |
| `--report_type`  | The report type that's desired [BASIC]                                    | str  | XML                                                                        |
| `--output`       | Location for report output                                                | path | /User/me/my_project/logs                                                   |
| `--exit`         | Exit with Code 0 regardless of vulnerability findings. [False]            | bool | True                                                                       |
| `--ignore`       | Ignore a CVE or package                                                   | str  | requests                                                                   |
| `--include_dev`  | Include develop dependencies from Pipfile.lock [False]                    | bool | True                                                                       |
| `--sbom`         | Must be provided, along with `--output` to generate an SBOM [False]       | bool | True                                                                       |
| `--sbom_format`  | Whether the generated SBOM should be a JSON or XML file. [JSON]           | str  | JSON                                                                       |
| `--enable_sast`  | Whether SAST checks should be run [False]                                 | bool | True                                                                       |
| `--sast_id_exclude`  | Whether a SAST check should be ignored                                | str  | O001                                                                       |
| `--sast_dir`     | Which directory should SAST checks run against                            | path | /User/me/my_project/src                                                                        |

### via environment variables
| Variable Name         | Corresponding Arg |
|-----------------------|-------------------|
| OCHRONA_DEBUG_LOGGING | `--debug`         |
| OCHRONA_IGNORED_VULNS | `--ignore`        |

### via .ochrona.yml
There is an empty `.ochrona.yml` file included in the repo.

| Key | Description | Type | Example |
|-|-|-|-|
| `dir` | Directory to recursively search for dependencies files to scan [.] | path | /User/me/my_project |
| `exclude_dir` | Directory names that should be excluded from recursive search. | list | build |
| `file` | Single dependency file to scan | file | /User/me/my_project/requirements.txt |
| `debug` | Enable debug logging [false] | bool | true |
| `silent` | Silent mode [false] | bool | true |
| `report_type` | The report type that's desired [BASIC] | str | XML |
| `report_location` | Location for report output [.] | path | /User/me/my_project/logs |
| `exit` | Exit with Code 0 regardless of vulnerability findings [false] | bool | true |
| `ignore` | Ignore a CVE or package name. Supports multiple values. | str | requests |
| `include_dev` | Include develop dependencies from files that support dev/required dependencies [false] | bool | true |
| `color_output` | Whether or not std out text should use color. Note: this is enabled by default when running in a non-Windows environment [true] | bool | false |
| `policies` | Policies are a way of defining additional checks against your dependencies. See [here](#policies) for more details | array | [details](#policies) |
| `sbom` | SBOM will only be generated if this argument is supplied. `report_location` also must be specified to generate an SBOM. See [here](#sbom) for more details about SBOMs [false] | bool | false |
| `sbom_format` | Whether the generated SBOM should be a JSON or XML file. [JSON] | str | JSON |
| `enable_sast` | Whether SAST checks should be run [False] | bool | true |
| `sast_id_exclude` | Whether a SAST check should be ignored. See list of SAST IDs [here](#sast-checks). Supports multiple values. | str | O001 |
| `sast_dir` | Which directory should SAST checks run against. [.] | path | /User/me/my_project/src |

**Example**:
```
# debug: true
# silent: false
# dir: .
# report_type: JSON
# report_location: .
# ignore: 
# - requests
# include_dev: false
# color_output: false
# policies:
#  - license_type NIN APSL,GPL-PA,JSON
# sbom: true
# sbom_format: JSON
# enable_sast: true
# sast_id_exclude:
#  - O001
# sast_dir: ./src
```

# Policies
Policies are a way to add additional check to your Python dependency usage. Policies can be defined using conditional and logical syntax. These generic policy definitions allow you to define unique, custom policies to fit your need, and they can be extensible as new fields and capabilities are added.

Policy vioations are not the same as vulnerabilities, however violations will cause Ochrona to emit a failure exit code and the output will include details about the policy violation.

## Policy Syntax
At their most basic, policies are defined using conditional statements and logical operators. A conditional statement is structured as `<field><operator><value>`, for example, `license_type == MIT`. Whitespace is always ignored during policy evaluation.

### Allowed Fields
| Name | Description |
|-|-|
| `name` | The name of a package. |
| `license_type` | An [SPDX](https://spdx.org/licenses/) license type for a package. |
| `latest_version` | The most recent version of a package. |
| `latest_update` | The timestamp for when a package was last updated. ISO-8601 Format `YYYY-MM-DDTHH:MM-SS.ffffffZ` |
| `release_count` | The number of releases a package has on Pypi. |

### Allowed Conditional Operators
| Operator | Description |
|-|-|
| `==` | An equals operator for comparing exact string matches. |
| `!=` | A NOT equals operators for non-matching strings. |
| `<` | Less than, for comparing numerical or string values. |
| `<=` | Less than or equal to. |
| `>` | Greater than, for comparing numerical or string values. |
| `>=` | Greater than or equal to. |
| `IN` | For checking whether a value exists within a set. Values used with `IN` should be comma separated. |
| `NIN` | For checking that a value does not exist within a set. Values used with `NIN` should be comma separated. |

### Allowed Logical Operators
| Operator | Description |
|-|-|
| `AND` | For checking that both adjacent conditions are true. |
| `OR` | For checking that at least one adjacent condition is true. |

### Special Values
| Value | Description |
|-|-|
| `NOW-N` | Shorthand for an ISO 8601 formatted date in the past. `N` will be an integer number of days. |
| `*` | Match ANY value, only works with `==` operator. |

### Precedence
Policies allow the usage of `(` and `)` to indicate evaluation precedence and grouping. 
Example ```(license_type==Apache-2.0 OR license_type==MIT) AND latest_update < NOW-30```

### Policy Examples
```
# Policy to check that a license type is in my aproved list
license_type IN MIT,ISC,Apache-2.0

# Policy to check that all packages have been updated this year
latest_update >= NOW-365
```

# SBOM
Software Bill-of-Materials (SBOM) are a list of the components used to build a piece of software. They aim to make the delivery and composition of software components more transparent. These documents can be useful for understanding software supply chains and ensuring license complaince. 

Ochrona has opted to support (CycloneDX)[https://cyclonedx.org/] as our SBOM standard of choice. CycloneDX is a lightweight software bill of materials (SBOM) standard designed for use in application security contexts and supply chain component analysis. CycloneDX is developed and support by (OWASP)[https://owasp.org/www-project-cyclonedx/].

To enable sbom generation, the `--sbom` arguement needs to be provided.

# Static Analysis Beta
Ochrona has introduced limited Static Application Security Testing (SAST) in version 2.0.0 as a beta feature. These check are run if the `--enable_sast` argument is provided. It will run recursively against all `.py` files found in the current working directory. 

## SAST Checks
| ID | Description |
|-|-|
| `O001` | `Checks for use of "exec" from the Standard Library.`|
| `O002` | `Checks for use of "eval" from the Standard Library.`|
| `O003` | `Checks for use of the "assert" keyword.`|
| `O004` | `Checks for use of "tarfile.extractall" from the Standard Library.`|
| `O005` | `Checks for use of "pickle.loads" from the Standard Library.`|
| `O006` | `Checks for use of "xml.etree.ElementTree.parse" from the Standard Library.`|
| `O101` | `Checks for use of "load" from PyYAML.`|
| `O102` | `Checks for usage of Requests with verify=False.`|
| `O103` | `Checks for usage of Flask with debug=True.`|


# Usage Examples
### Default Mode
```
$ ochrona
```
This will search for any supported dependency files recursively from the run location. It will output rules in the `BASIC`
format to stdout. The program will exit with an error exit code if any confirmed vulnerabilities are found.

### Standard error code with Junit XML reporting saved to file
```
$ ochrona --exit --report_type XML --output ./output
```

### Safe Import Mode
In this mode ochrona acts as a safe wrapper around standard pip installs to ensure that a package and it's dependencies are safe before installing. This action preemptively checks a package and only imports if no vulnerabilities are found. It can be used with a base package (i.e. `requests`), or with a package pinned to an exact version (i.e. `requests==2.21.0`). It also supports importing a `requirements.txt` style, the pip equivalent of `pip install -r <file>`.
```
$ ochrona --install <package_name>|<requirements.txt>
```

### stdin Support
Ochrona supports supplying dependencies via stdin and can accept a PEP-508 complaint (i.e. requirements.txt) formated string, or a single dependency. Single dependencies can be supplied as the first argument or piped.

#### Single dependency via stdin
```
$ ochrona urllib3==1.26.4
$ echo "urllib3==1.26.4" | ochrona
```

#### Multi-dependency via stdin
```
$ pip freeze | ochrona
$ pipenv lock -r | ochrona
$ cat requirements.txt | ochrona
```

### Docker Support
Ochrona can be run via Docker. This is useful for the paranoid who may worry that an installed module could have modified the Python package namespace and allow malicious packages to bypass Ochrona's security checks. We've added this support in response to [CVE-2020-5252](https://mulch.dev/blog/CVE-2020-5252-python-safety-vuln/) which was disclosed prior to Ochrona and affects several other similar tools.

#### Dockerized Ochrona
```
$ pip freeze | docker run -i --rm ochrona/ochrona ochrona
```
#### Dockerized Ochrona with environment variables
```
$ pip freeze | docker run -i -e OCHRONA_IGNORED_VULNS=requests --rm ochrona/ochrona ochrona
```

# Output Formats
Ochrona supports several built in output options include a `BASIC` and `FULL` plaintext reports, a Junit style `XML` report, a `JSON` style report for incorporating with other tools, and and `HTML` summarized report.

### Basic
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_basic.png"/></p>](https://ochrona.dev)

### Full
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_full.png"/></p>](https://ochrona.dev)

### XML (Junit)
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_xml.png"/></p>](https://ochrona.dev)

### JSON
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_json.png"/></p>](https://ochrona.dev)

### HTML
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_HTML.png"/></p>](https://ochrona.dev)



# Represent!
[![Ochrona](https://img.shields.io/badge/secured_by-ochrona-blue)](https://ochrona.dev)

Let the world know you're keeping your project safe with Ochrona. Add our shield to your `README.md` by adding the following line.
```
[![Ochrona](https://img.shields.io/badge/secured_by-ochrona-blue)](https://ochrona.dev)
```

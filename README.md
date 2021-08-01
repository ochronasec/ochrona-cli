[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_logo.png" width="500"/></p>](https://ochrona.dev)

[![Ochrona](https://img.shields.io/badge/secured_by-ochrona-blue?style=flat-square)](https://ochrona.dev)
[![PyPI](https://img.shields.io/pypi/v/ochrona?color=blue&style=flat-square)](https://pypi.org/project/ochrona/)
[![Versions](https://img.shields.io/pypi/pyversions/ochrona?color=blue&logo=python&logoColor=white&style=flat-square)](https://pypi.org/project/ochrona/)
[![License](https://img.shields.io/pypi/l/ochrona?color=blue&label=License&style=flat-square)](https://pypi.org/project/ochrona/)
[![Downloads](https://img.shields.io/pypi/dm/ochrona?color=blue&label=Downloads&style=flat-square)](https://pypi.org/project/ochrona/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)
[![codecov](https://codecov.io/gh/ochronasec/ochrona-cli/branch/master/graph/badge.svg?token=uWNZiXnXto?style=flat-square)](https://codecov.io/gh/ochronasec/ochrona-cli)

- [Overview](#overview)
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
    + [Policy Types](#policy-types)
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
| `ignore` | Ignore a CVE or package name | str | requests |
| `include_dev` | Include develop dependencies from files that support dev/required dependencies [false] | bool | true |
| `color_output` | Whether or not std out text should use color. Note: this is enabled by default when running in a non-Windows environment [true] | bool | false |
| `policies` | Policies are a way of defining additional checks against your dependencies. See [here](#policies) for more details | dict | [details](#policies) |

**Example**:
```
# debug: true
# silent: false
# dir: .
# report_type: JSON
# report_location: .
# ignore: requests
# include_dev: false
# color_output: false
# policies:
#  - policy_type: license_type
#    deny_list: APSL,GPL-PA,JSON
```

# Policies
Policies are a way to add additional check to your Python dependency usage. A policy is defined using its name and one or more conditions which are evaluated at scan time.

For example, the `license_type` policy allows you to be alerted if one of your dependency's open-source license is not part of your "Allow List" or if it uses a license from your "Deny List".

Policy vioations are not the same as vulnerabilities, however they will cause Ochrona to emit a failure exit code and the output will include details about the policy violation.

## Policy Types
| Name | Description | Fields |
|-|-|-|
| `package_name` | Allows for checking whether the dependencies used are all from an `allow_list` or contain any values from a `deny_list`. You may define `allow_list` or `deny_list`, but not both. Field values should be defined as a comma-separated string. | `allow_list`, `deny_list` | 
| `license_type` | Allows for checking whether the licenses of dependencies used are all from an `allow_list` or contain any values from a `deny_list`. You may define `allow_list` or `deny_list`, but not both. Field values should be defined as a comma-separated string. | `allow_list`, `deny_list` | 

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
Ochrona supports several built in output options include a `BASIC` and `FULL` plaintext reports, as well as a Junit style `XML` report or a `JSON` style report for incorporating with other tools.

### Basic
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_basic.png"/></p>](https://ochrona.dev)

### Full
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_full.png"/></p>](https://ochrona.dev)

### XML (Junit)
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_xml.png"/></p>](https://ochrona.dev)

### JSON
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_json.png"/></p>](https://ochrona.dev)


# Represent!
[![Ochrona](https://img.shields.io/badge/secured_by-ochrona-blue)](https://ochrona.dev)

Let the world know you're keeping your project safe with Ochrona. Add our shield to your `README.md` by adding the following line.
```
[![Ochrona](https://img.shields.io/badge/secured_by-ochrona-blue)](https://ochrona.dev)
```

[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_logo.png" width="500"/></p>](https://ochrona.dev)

[![PyPI](https://img.shields.io/pypi/v/ochrona)](https://pypi.org/project/ochrona/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Build Status](https://travis-ci.com/ochronasec/ochrona-cli.svg?token=9JDALtMe5VnkYyLdqiN6&branch=master)](https://travis-ci.com/ochronasec/ochrona-cli)
[![codecov](https://codecov.io/gh/ochronasec/ochrona-cli/branch/master/graph/badge.svg?token=uWNZiXnXto)](https://codecov.io/gh/ochronasec/ochrona-cli)


Ochrona is a command line tool for checking python projects for vulnerabilities in their dependencies. 
Ochrona has a free-tier license which allows 25 scans per month. 

You can sign up for an API key at https://ochrona.dev.

We care deeply about Developer Experience (dx), if you have any feedback or run into issues please open an issue [here](https://github.com/ochronasec/ochrona-cli/issues).

### Supported file types
- `*requirements*.txt`
- `Pipfile.lock`
- `poetry.lock`
- `setup.py`

# Installation

### via pip
```
pip install ochrona
```

### via pipenv
```
pipenv install <--dev> ochrona
```

# Configuration
### via command line args
| Arg              | Description                                                               | Type | Example                                                                    |
|------------------|---------------------------------------------------------------------------|------|----------------------------------------------------------------------------|
| `--api_key`      | Ochrona API Key                                                           | str  | abc123                                                                     |
| `--dir`          | Directory to recursively search for dependencies files to scan [.]        | path | /User/me/my_project                                                        |
| `--file`         | Single dependency file to scan                                            | file | /User/me/my_project/requirements.txt                                       |
| `--debug`        | Enable debug logging [False]                                              | bool | True                                                                       |
| `--silent`       | Silent mode [False]                                                       | bool | True                                                                       |
| `--report_type`  | The report type that's desired [BASIC]                                    | str  | XML                                                                        |
| `--output`       | Location for report output                                                | path | /User/me/my_project/logs                                                   |
| `--exit`         | Exit with Code 0 regardless of vulnerability findings. [False]            | bool | True                                                                       |
| `--ignore`       | Ignore a CVE or package                                                   | str  | requests                                                                   |
| `--include_dev`  | Include develop dependencies from Pipfile.lock [False]                    | bool | True                                                                       |
| `--project_name` | The name of your project                                                  | str  | "My Example Project                                                        |
| `--alert_config` | Alert configuration for use with DADA. This is expressed as a json string | str  | '{"alerting_addresses": "test@ohrona.dev", "alerting_rules": "not:boto3"}' |

### via environment variables
| Variable Name         | Corresponding Arg |
|-----------------------|-------------------|
| OCHRONA_API_KEY       | `--api_key`       |
| OCHRONA_DEBUG_LOGGING | `--debug`         |
| OCHRONA_IGNORED_VULNS | `--ignore`        |

### via .ochrona.yml
There is an empty `.ochrona.yml` file included in the repo. 
Example:
```
# api_key: <your key>
# debug: true
# silent: false
# dir: .
# report_type: JSON
# report_location: .
# ignore: requests
# include_dev: false
# project_name: my_test_project
# alert_config:
#   alerting_addresses: test@web.com
#   alerting_rules: not:boto3
```

# Usage Examples
### Full Default Mode
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
In this mode ochrona acts as a safe wrapper around standard pip installs to ensure that a package and it's dependencies are safe before installing. This action preemptively checks a package against the Ochrona API and only imports if no vulnerabilities are found. It can be used with a base package (i.e. `requests`), or with a package pinned to an exact version (i.e. `requests==2.21.0`). It also supports importing a `requirements.txt` style, the pip equivalent of `pip install -r <file>`. 
```
$ ochrona --install <package_name>|<requirements.txt>
```

# Reports
Ochrona supports several built in output options include a `BASIC` and `FULL` plaintext reports, as well as a Junit style `XML` report or a `JSON` style report for incorporating with other tools.

### Basic
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_basic.png" width="500"/></p>](https://ochrona.dev)

### Full
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_full.png" width="500"/></p>](https://ochrona.dev)

### XML (Junit)
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_xml.png" width="500"/></p>](https://ochrona.dev)

### JSON
[<p align="center"><img src="https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_json.png" width="500"/></p>](https://ochrona.dev)

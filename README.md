[![ochrona](https://raw.githubusercontent.com/ochrona/ochrona-cli/master/resources/ochrona_logo.png)](https://ochrona.dev)

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Ochrona is a command line tool for checking python projects for vulnerabilities in their dependencies. Ochrona has a free-tier license which allows 25 scans per month. You can sign up for an API key at https://ochrona.dev.

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
| Arg             | Description                                                        | Type | Example                              |
|-----------------|--------------------------------------------------------------------|------|--------------------------------------|
| `--api_key`     | Ochrona API Key                                                    | str  | abc123                               |
| `--dir`         | Directory to recursively search for dependencies files to scan [.] | path | /User/me/my_project                  |
| `--file`        | Single dependency file to scan                                     | file | /User/me/my_project/requirements.txt |
| `--debug`       | Enable debug logging [False]                                       | bool | True                                 |
| `--silent`      | Silent mode [False]                                                | bool | True                                 |
| `--report_type` | The report type that's desired [BASIC]                             | str  | XML                                  |
| `--output`      | Location for report output                                         | path | /User/me/my_project/logs             |
| `--exit`        | Exit with Code 0 regardless of vulnerability findings. [False]     | bool | True                                 |

### via environment variables
| Variable Name         | Corresponding Arg |
|-----------------------|-------------------|
| OCHRONA_API_KEY       | `--api_key`       |
| OCHRONA_DEBUG_LOGGING | `--debug`         |

### via .ochrona.yml
There is an empty `.ochrona.yml` file included in the repo. 
Example:
```
---
# api_key: <your key>
# debug: true
# silent: false
# dir: .
# report_type: JSON
# report_location: .
```

# Usage
```
$ ochrona 
```


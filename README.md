[![ochrona](https://github.com/ochronasec/ochrona-cli/raw/master/resources/ochrona_logo.png)](https://ochrona.dev)

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
| Arg                   | Description                                                        | Type | Example                              |
|-----------------------|--------------------------------------------------------------------|------|--------------------------------------|
| `--api_key`           | Ochrona API Key                                                    | str  | abc123                               |
| `--dir`               | Directory to recursively search for dependencies files to scan [.] | path | /User/me/my_project                  |
| `--file`              | Single dependency file to scan                                     | file | /User/me/my_project/requirements.txt |
| `--debug`             | Enable debug logging [False]                                       | bool | True                                 |
| `--silent`            | Silent mode [False]                                                | bool | True                                 |
| `--report_type`       | The report type that's desired [BASIC]                             | str  | XML                                  |
| `--output`            | Location for report output                                         | path | /User/me/my_project/logs             |
| `--exit`              | Exit with Code 0 regardless of vulnerability findings. [False]     | bool | True                                 |
| `--ignore`           | Ignore a CVE or package                                             | str  | requests                             |
| `--include_dev`      | Include develop dependencies from Pipfile.lock [False]              | bool | True                                 |

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
```

# Usage Examples
### Full default mode
```
$ ochrona 
```
This will search for any supported dependency files recursively from the run location. It will output rules in the `BASIC`
format to stdout. The program will exit with an error exit code if any confirmed vulnerabilities are found.

### Standard error code with Junit XML reporting saved to file
```
$ ochrona --exit --report_type XML --output ./output
```

# Reports

### Basic
```
Report 1 of 1
╞====================================================================================================╡
| Source: ./requirements.txt
╞====================================================================================================╡
| ⚠️  Vulnerability Detected!
╞----------------------------------------------------------------------------------------------------╡
| Package -- requests
╞----------------------------------------------------------------------------------------------------╡
| Installed Version -- requests==2.19.0
╞----------------------------------------------------------------------------------------------------╡
| CVE -- CVE-2018-18074
╞----------------------------------------------------------------------------------------------------╡
| Severity -- 9.8 
╞----------------------------------------------------------------------------------------------------╡
| Affected Versions --  =0.0.1, =0.2.0, =0.2.1, =0.2.2, =0.2.3, =0.2.4, =0.3.0, =0.3.1, =0.3.2,
=0.3.3, =0.3.4, =0.4.0, =0.4.1, =0.5.0, =0.5.1, =0.6.0, =0.6.1, =0.6.2, =0.6.3, =0.6.4, =0.6.5,
=0.6.6, =0.7.0, =0.7.1, =0.7.2, =0.7.3, =0.7.4, =0.7.5, =0.7.6, =0.8.0, =0.8.1, =0.8.2, =0.8.3,
=0.8.4, =0.8.5, =0.8.6, =0.8.7, =0.8.8, =0.8.9, =0.9.0, =0.9.1, =0.9.2, =0.9.3, =0.10.0, =0.10.1,
=0.10.2, =0.10.3, =0.10.4, =0.10.5, =0.10.6, =0.10.7, =0.10.8, =0.11.0, =0.11.1, =0.11.2, =0.12.0,
=0.12.1, =0.13.0, =0.13.1, =0.13.2, =0.13.3, =0.13.4, =0.13.5, =0.13.6, =0.13.7, =0.13.8, =0.13.9,
=0.14.0, =0.14.1, =0.14.2, =1.0.0, =1.0.1, =1.0.2, =1.0.3, =1.0.4, =1.1.0, =1.2.0, =1.2.1, =1.2.2,
=1.2.3, =2.0, =2.0.0, =2.0.1, =2.1.0, =2.2.0, =2.2.1, =2.3.0, =2.4.0, =2.4.1, =2.4.2, =2.4.3,
=2.5.0, =2.5.1, =2.5.2, =2.5.3, =2.6.0, =2.6.1, =2.6.2, =2.7.0, =2.8.0, =2.8.1, =2.9.0, =2.9.1,
=2.9.2, =2.10.0, =2.11.0, =2.11.1, =2.12.0, =2.12.1, =2.12.2, =2.12.3, =2.12.4, =2.12.5, =2.13.0,
=2.14.0, =2.14.1, =2.14.2, =2.15.0, =2.15.1, =2.16.0, =2.16.1, =2.16.2, =2.16.3, =2.16.4, =2.16.5,
=2.17.0, =2.17.1, =2.17.2, =2.17.3, =2.18.0, =2.18.1, =2.18.2, =2.18.3, =2.18.4, =2.19.0,
=2.19.1
╞----------------------------------------------------------------------------------------------------╡
╞====================================================================================================╡

```

### Full
```
Report 1 of 1
╞====================================================================================================╡
| Source: ./tests/test_data/fail/requirements.txt
╞====================================================================================================╡
| ⚠️  Vulnerability Detected!
╞----------------------------------------------------------------------------------------------------╡
| Package -- requests
╞----------------------------------------------------------------------------------------------------╡
| Installed Version -- requests==2.19.0
╞----------------------------------------------------------------------------------------------------╡
| Reason -- Flagged as a confirmed vulnerability because version was an exact match for
dependency: requests
╞----------------------------------------------------------------------------------------------------╡
| CVE -- CVE-2018-18074
╞----------------------------------------------------------------------------------------------------╡
| Vulnerability Publish Date -- 2018-10-09T17:29Z
╞----------------------------------------------------------------------------------------------------╡
| Severity -- 9.8 
╞----------------------------------------------------------------------------------------------------╡
| Description -- The Requests package before 2.20.0 for Python sends an HTTP Authorization
header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier
for remote attackers to discover credentials by sniffing the network.
╞----------------------------------------------------------------------------------------------------╡
| Affected Version(s) --  =0.0.1, =0.2.0, =0.2.1, =0.2.2, =0.2.3, =0.2.4, =0.3.0, =0.3.1,
=0.3.2, =0.3.3, =0.3.4, =0.4.0, =0.4.1, =0.5.0, =0.5.1, =0.6.0, =0.6.1, =0.6.2, =0.6.3, =0.6.4,
=0.6.5, =0.6.6, =0.7.0, =0.7.1, =0.7.2, =0.7.3, =0.7.4, =0.7.5, =0.7.6, =0.8.0, =0.8.1, =0.8.2,
=0.8.3, =0.8.4, =0.8.5, =0.8.6, =0.8.7, =0.8.8, =0.8.9, =0.9.0, =0.9.1, =0.9.2, =0.9.3, =0.10.0,
=0.10.1, =0.10.2, =0.10.3, =0.10.4, =0.10.5, =0.10.6, =0.10.7, =0.10.8, =0.11.0, =0.11.1, =0.11.2,
=0.12.0, =0.12.1, =0.13.0, =0.13.1, =0.13.2, =0.13.3, =0.13.4, =0.13.5, =0.13.6, =0.13.7, =0.13.8,
=0.13.9, =0.14.0, =0.14.1, =0.14.2, =1.0.0, =1.0.1, =1.0.2, =1.0.3, =1.0.4, =1.1.0, =1.2.0, =1.2.1,
=1.2.2, =1.2.3, =2.0, =2.0.0, =2.0.1, =2.1.0, =2.2.0, =2.2.1, =2.3.0, =2.4.0, =2.4.1, =2.4.2,
=2.4.3, =2.5.0, =2.5.1, =2.5.2, =2.5.3, =2.6.0, =2.6.1, =2.6.2, =2.7.0, =2.8.0, =2.8.1, =2.9.0,
=2.9.1, =2.9.2, =2.10.0, =2.11.0, =2.11.1, =2.12.0, =2.12.1, =2.12.2, =2.12.3, =2.12.4, =2.12.5,
=2.13.0, =2.14.0, =2.14.1, =2.14.2, =2.15.0, =2.15.1, =2.16.0, =2.16.1, =2.16.2, =2.16.3, =2.16.4,
=2.16.5, =2.17.0, =2.17.1, =2.17.2, =2.17.3, =2.18.0, =2.18.1, =2.18.2, =2.18.3, =2.18.4, =2.19.0,
=2.19.1
╞----------------------------------------------------------------------------------------------------╡
| References -- 
        http://docs.python-requests.org/en/master/community/updates/#release-and-version-history
        http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00024.html
        https://access.redhat.com/errata/RHSA-2019:2035
        https://bugs.debian.org/910766
        https://github.com/requests/requests/commit/c45d7c49ea75133e52ab22a8e9e13173938e36ff
        https://github.com/requests/requests/issues/4716
        https://github.com/requests/requests/pull/4718
        https://usn.ubuntu.com/3790-1/
        https://usn.ubuntu.com/3790-2/ 
╞====================================================================================================╡
╞====================================================================================================╡
```

### XML (Junit)
```
<?xml version="1.0" ?>
<testsuites>
   <testsuite tests="84">
      <properties>
         <property name="source" value="./tests/test_data/fail/requirements.txt"/>
         <property name="timestamp" value="2019-10-18T15:53:57.145247"/>
      </properties>
      <testcase classname="ochronaDependencyVulnCheck" name="requests==2.19.0">
         <failure type="confirmed_vulnerability">The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.</failure>
      </testcase>
      <testcase classname="ochronaDependencyVulnCheck" name="Click==7.0"/>
      <testcase classname="ochronaDependencyVulnCheck" name="Flask==1.1.1"/>
      <testcase classname="ochronaDependencyVulnCheck" name="itsdangerous==1.1.0"/>
      <testcase classname="ochronaDependencyVulnCheck" name="Jinja2==2.10.1"/>
      <testcase classname="ochronaDependencyVulnCheck" name="MarkupSafe==1.1.1"/>
      <testcase classname="ochronaDependencyVulnCheck" name="Werkzeug==0.15.4"/>
      <testcase classname="ochronaDependencyVulnCheck" name="coverage"/>
      ...
      <testcase classname="ochronaDependencyVulnCheck" name="python-dotenv"/>
   </testsuite>
</testsuites>
```

### JSON
```
{
    "meta": {
        "source": "./tests/test_data/fail/requirements.txt",
        "timestamp": "2019-10-18T16:04:45.312481"
    },
    "findings": [
        {
            "owner": "python-requests",
            "repo_url": "http://python-requests.org",
            "ochrona_id": "595ace88-3240-468b-a2a3-331e2439e659",
            "references": [
                "http://docs.python-requests.org/en/master/community/updates/#release-and-version-history",
                "http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00024.html",
                "https://access.redhat.com/errata/RHSA-2019:2035",
                "https://bugs.debian.org/910766",
                "https://github.com/requests/requests/commit/c45d7c49ea75133e52ab22a8e9e13173938e36ff",
                "https://github.com/requests/requests/issues/4716",
                "https://github.com/requests/requests/pull/4718",
                "https://usn.ubuntu.com/3790-1/",
                "https://usn.ubuntu.com/3790-2/"
            ],
            "cwe_id": "CWE-255",
            "impact": {
                "a": "HIGH",
                "ac": "LOW",
                "pr": "NONE",
                "c": "HIGH",
                "vector_string": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "i": "HIGH",
                "impact_score": "5.9",
                "cvss3_severity": "CRITICAL",
                "cvss2_severity": "MEDIUM",
                "s": "UNCHANGED",
                "ui": "NONE",
                "cvss2_score": "5.0",
                "av": "NETWORK",
                "exploitability_score": "3.9",
                "cvss3_score": "9.8"
            },
            "description": "The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.",
            "language": "python",
            "ochrona_severity_score": "9.8",
            "repository_summary": "Python HTTP for Humans.",
            "license": "Apache 2.0",
            "latest_version": "2.22.0",
            "cve_id": "CVE-2018-18074",
            "affected_versions": [
                {
                    "version_value": "0.0.1",
                    "operator": "="
                },
                {
                    "version_value": "0.2.0",
                    "operator": "="
                },
                ...
                {
                    "version_value": "2.19.1",
                    "operator": "="
                }
            ],
            "name": "requests",
            "publish_date": "2018-10-09T17:29Z",
            "found_version": "requests==2.19.0",
            "reason": "Flagged as a confirmed vulnerability because version was an exact match for dependency: requests"
        }
    ]
}
```
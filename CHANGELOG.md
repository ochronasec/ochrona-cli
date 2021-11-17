# Change Log

## 1.2.0
- Use SPDX official license list for dependency license IDs
- Include (Package URL i.e. purl)[https://github.com/package-url/purl-spec] in Dependency model
- Include discovered package hashes in Dependency model

## 1.1.0
- Introduced new dynamic policies
-- Existing policy types, `package_name` and `license_type` will now be known as `legacy` policies.
-- New policy types can be defined as logical condition strings (i.e. `license_type IN MIT,ISC,Apache-2.0`)

## 1.0.2
- Avoid errors when processing dependency specifications with invalid characters

## 1.0.1
- Fixed bug where vuln processing could fail if version was unspecified

## 1.0.0
- Operating model changed from API based to local analysis
- Added support for policy checks
- Removed support for project and DADA configuration
- Removed the need for any account, credentials, or usage limits

## 0.2.1
- Bump urllib3 dependency

## 0.2.0
- Added support for policies

## 0.1.4
- Updated PyYAML

## 0.1.3
- Updated documentation
- Added Docker support

## 0.1.2
- In some interpreters click accepts an empty string as an arguments, while others return None 

## 0.1.1
- Allow ochrona to accept piped input

## 0.1.0
- Updated to support new authentication provider

## 0.0.18
- Fixed bug where file name could not be provided from config
- Friendly Error when no dependency files are found

## 0.0.17
- Improved output formatting
- Added ability to exclude directories

## 0.0.16
- Fixed incorrect report count if a dependency file was empty

## 0.0.15
- Fix for AttributeError when parsing some setup.py files
- Additional cleanup for requirements files with specified hashes or python version requirements

## 0.0.14
- Additional minor fixes when running in a Windows environment

## 0.0.13
- Allow colored output to be disabled and auto-disable for Windows users
- Fixed API error on empty requirements file

## 0.0.12
- Fix import error when running in some scenarios

## 0.0.11
- Added support for Conda environment.yml files
- Added support for tox.ini files
- Added support for constraints.txt files

## 0.0.10
- Added type hints and mypy support
- Improved XML reporting

## 0.0.9
- Added support for safe pip -r style installs for requirements.txt style files
- Prevent using requirements.txt lines that are not direct dependencies
- Added Package license to FULL output report

## 0.0.8
- Added support for safe pip installs by doing a pre-install check.

## 0.0.7
- Added support for including poetry.lock and setup.py dependency files

## 0.0.4
- Added support for including dev dependencies in Pipfile.lock files
# Change Log

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
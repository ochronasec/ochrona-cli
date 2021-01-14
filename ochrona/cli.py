#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Ochrona-cli
:author: ascott
"""

import json
import sys

import click
from typing import Optional

from ochrona.config import OchronaConfig
from ochrona.exceptions import OchronaException, OchronaAPIException
from ochrona.file_handler import rfind_all_dependencies_files, parse_to_payload
from ochrona.import_wrapper import SafeImport
from ochrona.logger import OchronaLogger
from ochrona.reporter import OchronaReporter
from ochrona.ochrona_rest_client import OchronaAPIClient


@click.command()
@click.option("--api_key", help="Ochrona API Key (https://ochrona.dev).")
@click.option(
    "--dir",
    help="Directory to recursively search for dependencies files.",
    type=click.Path(exists=True),
)
@click.option("--file", "-r", help="Dependency file to use.", type=click.File("r"))
@click.option("--debug", help="Enable debug logging.", default=False, is_flag=True)
@click.option("--silent", help="Silent mode.", default=False, is_flag=True)
@click.option(
    "--report_type",
    help=f"The report type that's desired. Options ({OchronaConfig.REPORT_OPTIONS}",
    default="BASIC",
)
@click.option(
    "--output", help=f"Location for report output", type=click.Path(exists=True)
)
@click.option(
    "--exit",
    help="Exit with Code 0 regardless of vulnerability findings.",
    default=False,
    is_flag=True,
)
@click.option("--ignore", help="Ignore vulnerabilities by CVE or package name.")
@click.option(
    "--include_dev",
    help="Check dev dependencies in Pipfile.lock",
    default=False,
    is_flag=True,
)
@click.option("--project_name", help="The name of your project.")
@click.option(
    "--alert_config",
    help="The Alert configuration for your project. This should be a json string with quotation marks escaped.",
)
@click.option("--install", help="A safe wrapper for pip --install")
def run(
    api_key: Optional[str],
    dir: Optional[str],
    file: Optional[str],
    debug: bool,
    silent: bool,
    report_type: Optional[str],
    output: Optional[str],
    exit: bool,
    ignore: Optional[str],
    include_dev: bool,
    project_name: Optional[str],
    alert_config: Optional[str],
    install: Optional[str],
):
    config = OchronaConfig(
        api_key=api_key,
        dir=dir,
        file=file,
        debug=debug,
        silent=silent,
        report_type=report_type,
        report_location=output,
        exit=exit,
        ignore=ignore,
        include_dev=include_dev,
        project_name=project_name,
        alert_config=alert_config,
    )
    log = OchronaLogger(config=config)
    client = OchronaAPIClient(logger=log, config=config)
    if install:
        # Install mode
        try:
            importer = SafeImport(logger=log, client=client)
            importer.install(package=install)
        except OchronaException as ex:
            OchronaLogger.static_error(ex)
            sys.exit(1)
    else:
        # Regular operational check
        reporter = OchronaReporter(log, config)
        if not config.silent:
            log.header()

        files = rfind_all_dependencies_files(log, config.dir, config.file)

        try:
            results = []
            for file_ in files:
                payload = parse_to_payload(log, file_, config)
                if payload.get("dependencies") != []:
                    results.append(client.analyze(json.dumps(payload)))
            if results == []:
                log.warn(f"No dependencies found in {', '.join(files)}")
            reporter.report_collector(files, results)
            if config.alert_config is not None and config.project_name is not None:
                client.update_alert(config=config)
        except OchronaAPIException as ex:
            OchronaLogger.static_error(ex)
            sys.exit(1)


if __name__ == "__main__":
    try:
        run()
    except OchronaException as ex:
        OchronaLogger.static_error(ex)
        sys.exit(1)

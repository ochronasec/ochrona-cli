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
from ochrona.eval.eval import resolve
from ochrona.exceptions import (
    OchronaException,
    OchronaFileException,
)
from ochrona.file import (
    rfind_all_dependencies_files,
    parse_to_payload,
    parse_direct_to_payload,
)
from ochrona.importer import SafeImport
from ochrona.log import OchronaLogger
from ochrona.model.dependency_set import DependencySet
from ochrona.reporter import OchronaReporter


def get_direct(ctx, param, value):
    if not value and not click.get_text_stream("stdin").isatty():
        return click.get_text_stream("stdin").read().strip()
    else:
        return value


@click.command()
@click.argument("direct", callback=get_direct, required=False)
@click.option(
    "--dir",
    help="Directory to recursively search for dependencies files.",
    type=click.Path(exists=True),
)
@click.option(
    "--exclude_dir",
    help="Directories to Exclude.",
    type=str,
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
@click.option("--install", help="A safe wrapper for pip --install")
def run(
    direct: Optional[str],
    dir: Optional[str],
    exclude_dir: Optional[str],
    file: Optional[str],
    debug: bool,
    silent: bool,
    report_type: Optional[str],
    output: Optional[str],
    exit: bool,
    ignore: Optional[str],
    include_dev: bool,
    install: Optional[str],
):
    config = OchronaConfig(
        dir=dir,
        exclude_dir=exclude_dir,
        file=file,
        debug=debug,
        silent=silent,
        report_type=report_type,
        report_location=output,
        exit=exit,
        ignore=ignore,
        include_dev=include_dev,
    )
    log = OchronaLogger(config=config)
    if install:
        # Install mode
        try:
            importer = SafeImport(logger=log)
            importer.install(package=install)
        except OchronaException as ex:
            OchronaLogger.static_error(ex)
            sys.exit(1)
    else:
        # Regular operational check
        reporter = OchronaReporter(log, config)
        if not config.silent:
            log.header()

        direct = direct if direct != "" else None
        try:
            if direct is None:
                files = rfind_all_dependencies_files(
                    log, config.dir, config.exclude_dir, config.file
                )
            else:
                files = []
        except OchronaFileException as ex:
            OchronaLogger.static_error(ex)
            sys.exit(1)

        try:
            results = []
            for file_ in files:
                payload = parse_to_payload(log, file_, config)
                if payload.get("dependencies") != []:
                    results.append(resolve(**payload))
                else:
                    # can't leave empty otherwise result counts are off
                    results.append(DependencySet())
            if direct is not None:
                # use piped input directly and treat as PEP-508 format
                payload = parse_direct_to_payload(log, direct, config)
                if payload.get("dependencies") != []:
                    results.append(resolve(**payload))
                else:
                    # can't leave empty otherwise result counts are off
                    results.append(DependencySet())
            if results == []:
                log.warn(f"No dependencies found in {files}")
            reporter.report_collector(files, results)
        except OchronaException as ex:
            OchronaLogger.static_error(ex)
            sys.exit(1)


if __name__ == "__main__":
    try:
        run()
    except OchronaException as ex:
        OchronaLogger.static_error(ex)
        sys.exit(1)

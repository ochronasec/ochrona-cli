import ast
import glob
import os
import pathlib
from typing import Dict, List

from ochrona.config import OchronaConfig
from ochrona.model.sast_violation import SASTViolation

from ochrona.sast.plugins.base import BaseOchronaPlugin
from ochrona.sast.plugins.flask_debug import FlaskRunDebug
from ochrona.sast.plugins.pyyaml_load import PyyamlLoad
from ochrona.sast.plugins.stdlib_assert import StdLibAssert
from ochrona.sast.plugins.stdlib_exec_call import StdLibExecCall
from ochrona.sast.plugins.stdlib_eval_call import StdLibEvalCall
from ochrona.sast.plugins.stdlib_pickle_loads import StdLibPickleLoads
from ochrona.sast.plugins.stdlib_tarfile_extractall import StdLibTarfileExtractall
from ochrona.sast.plugins.stdlib_xml_parse import StdLibXMLParse
from ochrona.sast.plugins.requests_verify_false import RequestsVerifyFalse

PLUGIN_DICT: Dict[str, BaseOchronaPlugin] = {
    FlaskRunDebug._id: FlaskRunDebug,
    PyyamlLoad._id: PyyamlLoad,
    StdLibExecCall._id: StdLibExecCall,
    StdLibEvalCall._id: StdLibEvalCall,
    StdLibAssert._id: StdLibAssert,
    StdLibPickleLoads._id: StdLibPickleLoads,
    StdLibTarfileExtractall._id: StdLibTarfileExtractall,
    StdLibXMLParse._id: StdLibXMLParse,
    RequestsVerifyFalse._id: RequestsVerifyFalse,
}


def evaluate(config: OchronaConfig) -> List[SASTViolation]:
    """ """
    active_plugins: List[BaseOchronaPlugin] = configure_plugins(config=config)
    evaluation_paths: List[pathlib.Path] = find_all_python_files(config=config)
    violations: List[SASTViolation] = []
    # print(
    #     f"Evaluating {len(active_plugins)} active plugins in {len(evaluation_paths)} files"
    # )
    for path in evaluation_paths:
        violations += _evaluate_file(file_path=path, plugins=active_plugins)
    return violations


def configure_plugins(config: OchronaConfig):
    """ """
    return [
        plugin
        for i, plugin in PLUGIN_DICT.items()
        if i not in config.sast_id_exclusion_list
    ]


def find_all_python_files(config: OchronaConfig) -> List[pathlib.Path]:
    """ """
    search_path = f"{config.sast_dir or os.getcwd()}/**/*.py"
    found = [pathlib.Path(f) for f in glob.glob(search_path, recursive=True)]
    return found


def _evaluate_file(
    file_path: pathlib.Path, plugins: List[BaseOchronaPlugin]
) -> List[SASTViolation]:
    """
    Inner evaluation for each file - will run all plugins
    """
    violations: List[SASTViolation] = []
    with open(file_path) as f:
        source_code = f.read()

        tree = ast.parse(source_code)
        configured_plugins = [plugin(file_path=file_path) for plugin in plugins]
        for plugin in configured_plugins:
            plugin.visit(tree)
            violations += plugin.violations

    return violations

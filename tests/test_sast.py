import os

from ochrona.sast.eval import evaluate

dir_path = os.path.dirname(os.path.abspath(__file__))


class MockConfig:
    def __init__(self, dir, sast_id_exclusion_list=[]):
        self._dir = dir or os.path.dirname(os.path.abspath(__file__))
        self._sast_id_exclusion_list = sast_id_exclusion_list

    @property
    def sast_dir(self):
        return self._dir

    @property
    def sast_id_exclusion_list(self):
        return self._sast_id_exclusion_list


class TestSASTEvaluate:
    """
    Unit tests for sast:eval
    """

    pass


class TestSASTExec(TestSASTEvaluate):
    def test_exec_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/exec")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O001"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/exec/example_exec.py:1:0"
        )


class TestSASTEval(TestSASTEvaluate):
    def test_eval_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/eval")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O002"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/eval/example_eval.py:1:0"
        )


class TestSASTAssert(TestSASTEvaluate):
    def test_assert_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/assert")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O003"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/assert/example_assert.py:2:4"
        )


class TestSASTTarfile(TestSASTEvaluate):
    def test_tarfile_extractall_direct_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/tarfile/direct")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O004"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/tarfile/direct/example_tarfile.py:6:0"
        )

    def test_tarfile_extractall_ctx_manager_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/tarfile/ctx_manager")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O004"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/tarfile/ctx_manager/example_tarfile.py:6:4"
        )

    def test_tarfile_extractall_import_from_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/tarfile/import_from")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O004"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/tarfile/import_from/example_tarfile.py:9:0"
        )

    def test_tarfile_extractall_ctx_alias_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/tarfile/alias")
        violations = evaluate(config=conf)
        assert len(violations) == 2
        assert violations[0].id == "O004"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/tarfile/alias/example_tarfile.py:6:0"
        )
        assert violations[1].id == "O004"
        assert violations[1].location == os.path.normpath(
            f"{dir_path}/test_data/sast/tarfile/alias/example_tarfile.py:11:4"
        )


class TestSASTPickle(TestSASTEvaluate):
    def test_pickle_loads_direct_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/pickle/direct")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O005"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/pickle/direct/example_pickle.py:11:0"
        )

    def test_pickle_loads_alias_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/pickle/alias")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O005"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/pickle/alias/example_pickle.py:11:0"
        )

    def test_pickle_loads_import_from_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/pickle/import_from")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O005"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/pickle/import_from/example_pickle.py:11:0"
        )


class TestSASTPyyaml(TestSASTEvaluate):
    def test_pyyaml_load_direct_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/pyyaml/direct")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O101"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/pyyaml/direct/example_pyyaml.py:10:7"
        )

    def test_pyyaml_load_alias_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/pyyaml/alias")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O101"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/pyyaml/alias/example_pyyaml.py:10:7"
        )

    def test_pyyaml_load_import_from_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/pyyaml/import_from")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O101"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/pyyaml/import_from/example_pyyaml.py:10:7"
        )


class TestSASTXML(TestSASTEvaluate):
    def test_xml_parse_direct_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/xml/direct")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O006"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/xml/direct/example_xml.py:3:0"
        )

    def test_xml_parse_alias_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/xml/alias")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O006"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/xml/alias/example_xml.py:3:0"
        )

    def test_xml_parse_import_from_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/xml/import_from")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O006"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/xml/import_from/example_xml.py:3:5"
        )


class TestSASTRequests(TestSASTEvaluate):
    def test_requests_verify_direct_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/requests/direct")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O102"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/requests/direct/example_requests.py:3:7"
        )

    def test_requests_verify_alias_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/requests/alias")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O102"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/requests/alias/example_requests.py:3:7"
        )

    def test_requests_verify_import_from_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/requests/import_from")
        violations = evaluate(config=conf)
        assert len(violations) == 4
        assert violations[0].id == "O102"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/requests/import_from/example_requests.py:4:7"
        )
        assert violations[1].location == os.path.normpath(
            f"{dir_path}/test_data/sast/requests/import_from/example_requests.py:6:7"
        )
        assert violations[2].location == os.path.normpath(
            f"{dir_path}/test_data/sast/requests/import_from/example_requests.py:8:7"
        )
        assert violations[3].location == os.path.normpath(
            f"{dir_path}/test_data/sast/requests/import_from/example_requests.py:10:7"
        )


class TestSASTFlask(TestSASTEvaluate):
    def test_flask_debug_direct_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/flask/direct")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O103"
        assert violations[0].location == os.path.normpath(
            f"{dir_path}/test_data/sast/flask/direct/example_flask.py:5:0"
        )

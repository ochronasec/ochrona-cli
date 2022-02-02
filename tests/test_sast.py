import os

from ochrona.sast.eval import evaluate

dir_path = os.path.dirname(os.path.abspath(__file__))

class MockConfig:

    def __init__(self, dir, sast_id_exclusion_list=[]):
        self._dir = dir or os.path.dirname(os.path.abspath(__file__))
        self._sast_id_exclusion_list = sast_id_exclusion_list

    @property
    def dir(self):
        return self._dir

    @property
    def sast_id_exclusion_list(self):
        return self._sast_id_exclusion_list


class TestSASTEvaluate:
    """
    Unit tests for sast:eval
    """
    def test_exec_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/exec")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O001"
        assert violations[0].location == "/Users/andrewscott/Dev/ochrona-cli/tests/test_data/sast/exec/example_exec.py:1:0"

    def test_eval_found(self):
        conf = MockConfig(dir=f"{dir_path}/test_data/sast/eval")
        violations = evaluate(config=conf)
        assert len(violations) == 1
        assert violations[0].id == "O002"
        assert violations[0].location == "/Users/andrewscott/Dev/ochrona-cli/tests/test_data/sast/eval/example_eval.py:1:0"
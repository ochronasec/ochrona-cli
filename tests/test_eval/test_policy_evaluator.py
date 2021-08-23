from datetime import datetime, timedelta
from ochrona.eval.policy import policy_evaluate
from ochrona.eval.policy.evaluate import evaluate

class MockDependencySet:
    def __init__(self, flat_list=[], dependencies=[]):
        self.flat_list = flat_list
        self.dependencies = [MockDependency(**d) for d in dependencies]

class MockDependency:
    def __init__(self, **kwargs):
        self._reserved_license_type = kwargs.get("license_type")
        self._reserved_latest_update = kwargs.get("latest_update")
        self._reserved_latest_version = kwargs.get("latest_version")
        self._reserved_release_count = kwargs.get("release_count")
        self.license_type = kwargs.get("license_type")
        self.full = kwargs.get("full")

class TestPolicyEvaluator:

    def test_policy_evaluate_allow_list_pass(self):
        """
        Test allow_list policy pass
        """
        package_list = MockDependencySet(
            ["package_a==1.0.1.0", "package_b==1.0.0"]
        )
        policies = [
            {
                "policy_type": "package_name",
                "allow_list": "package_a,package_b",
                "deny_list": "",
            }
        ]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_policy_evaluate_allow_list_fail(self):
        """
        Test allow_list policy fail
        """
        package_list = MockDependencySet(
            ["package_a==1.0.1.0", "package_b==1.0.0"]
        )
        policies = [
            {
                "policy_type": "package_name",
                "allow_list": "package_a",
                "deny_list": "",
            }
        ]
        self.policy_evaluator_harness(package_list, policies, 1)

    def test_policy_evaluate_deny_list_pass(self):
        """
        Test deny_list policy pass
        """
        package_list = MockDependencySet(
            ["package_a==1.0.1.0", "package_b==1.0.0"]
        )
        policies = [
            {
                "policy_type": "package_name",
                "allow_list": "",
                "deny_list": "package_c",
            }
        ]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_policy_evaluate_deny_list_fail(self):
        """
        Test deny_list policy fail
        """
        package_list = MockDependencySet(
            ["package_a==1.0.1.0", "package_b==1.0.0"]
        )
        policies = [
            {
                "policy_type": "package_name",
                "allow_list": "",
                "deny_list": "package_a",
            }
        ]
        self.policy_evaluator_harness(package_list, policies, 1)

    def test_policy_evaluate_allow_list_spaces(self):
        """
        Test allow_list policy pass
        """
        package_list = MockDependencySet(
            ["package_a==1.0.1.0", "package_b==1.0.0"]
        )
        policies = [
            {
                "policy_type": "package_name",
                "allow_list": "package_a    ,    package_b    ",
                "deny_list": "",
            }
        ]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_policy_evaluate_invalid_policy(self):
        """
        Test allow_list policy pass
        """
        package_list = MockDependencySet(
            ["package_a==1.0.1.0", "package_b==1.0.0"]
        )
        policies = [
            {"policy_type": "something", "allow_list": "a,b,c", "deny_list": ""}
        ]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_license_policy_evaluate_allow_list_pass(self):
        """
        Test license allow_list policy pass
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = [
            {
                "policy_type": "license_type",
                "allow_list": "MIT,BSD-3-Clause",
                "deny_list": "",
            }
        ]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_license_policy_evaluate_allow_list_fail(self):
        """
        Test license allow_list policy fail
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "HPND"}]
        )
        policies = [
            {
                "policy_type": "license_type",
                "allow_list": "MIT,BSD-3-Clause",
                "deny_list": "",
            }
        ]
        self.policy_evaluator_harness(package_list, policies, 1)

    def test_license_policy_evaluate_deny_list_pass(self):
        """
        Test license deny_list policy pass
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = [
            {
                "policy_type": "license_type",
                "allow_list": "",
                "deny_list": "HPND",
            }
        ]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_license_policy_evaluate_deny_list_fail(self):
        """
        Test license deny_list policy fail
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "HPND"}]
        )
        policies = [
            {
                "policy_type": "license_type",
                "allow_list": "",
                "deny_list": "HPND,UNKNOWN",
            }
        ]
        self.policy_evaluator_harness(package_list, policies, 1)

    def test_generic_policy_evaluation_equals_pass(self):
        """
        Test generic policy evaluation == pass
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = ["license_type==MIT"]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_generic_policy_evaluation_equals_fail(self):
        """
        Test generic policy evaluation == fail
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = ["license_type==ISC"]
        self.policy_evaluator_harness(package_list, policies, 1)

    def test_generic_policy_evaluation_in_pass(self):
        """
        Test generic policy evaluation IN pass
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = ["license_type IN MIT,ISC"]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_generic_policy_evaluation_in_fail(self):
        """
        Test generic policy evaluation IN fail
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = ["license_type IN ISC,Apache-2.0"]
        self.policy_evaluator_harness(package_list, policies, 1)

    def test_generic_policy_evaluation_nequals_pass(self):
        """
        Test generic policy evaluation != pass
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = ["license_type!=ISC"]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_generic_policy_evaluation_nequals_fail(self):
        """
        Test generic policy evaluation != fail
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = ["license_type!=MIT"]
        self.policy_evaluator_harness(package_list, policies, 1)
    
    def test_generic_policy_evaluation_gt_pass(self):
        """
        Test generic policy evaluation > pass
        """
        past_days_10 = (datetime.now() - timedelta(10)).isoformat() + "Z"
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT", "latest_update": past_days_10}]
        )
        policies = ["latest_update > NOW-30"]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_generic_policy_evaluation_gt_fail(self):
        """
        Test generic policy evaluation > fail
        """
        past_days_100 = (datetime.now() - timedelta(100)).isoformat() + "Z"
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT", "latest_update": past_days_100}]
        )
        policies = ["latest_update > NOW-30"]
        self.policy_evaluator_harness(package_list, policies, 1)

    def test_generic_policy_evaluation_lt_pass_date(self):
        """
        Test generic policy evaluation < pass
        """
        past_days_100 = (datetime.now() - timedelta(100)).isoformat() + "Z"
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT", "latest_update": past_days_100}]
        )
        policies = ["latest_update < NOW-30"]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_generic_policy_evaluation_lt_pass_semver(self):
        """
        Test generic policy evaluation < pass
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT", "latest_version": "3.0.1"}]
        )
        policies = ["latest_version < 10.0.0"]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_generic_policy_evaluation_lt_pass_int(self):
        """
        Test generic policy evaluation < pass
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT", "release_count": 10}]
        )
        policies = ["release_count < 20"]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_generic_policy_evaluation_equals_AND_pass(self):
        """
        Test generic policy evaluation == pass
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = ["license_type==MIT AND license_type!=ISC"]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_generic_policy_evaluation_equals_AND_fail(self):
        """
        Test generic policy evaluation == pass
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = ["license_type==MIT AND license_type!=MIT"]
        self.policy_evaluator_harness(package_list, policies, 1)

    def test_generic_policy_evaluation_equals_OR_pass(self):
        """
        Test generic policy evaluation OR pass
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = ["license_type==MIT OR license_type==ISC"]
        self.policy_evaluator_harness(package_list, policies, 0)

    def test_generic_policy_evaluation_equals_OR_fail(self):
        """
        Test generic policy evaluation OR fail
        """
        package_list = MockDependencySet(
            [], [{"full": "fake==1.2.3", "license_type": "MIT"}]
        )
        policies = ["license_type==Apache-2.0 OR license_type==ISC"]
        self.policy_evaluator_harness(package_list, policies, 1)

    @staticmethod
    def policy_evaluator_harness(package_list, policies, expected_violation_count):
        """
        Test Harness for running policy evaluation tests.
        """
        result = policy_evaluate(dependencies=package_list, policies=policies)
        assert expected_violation_count == len(
            result
        ), f"Expected {expected_violation_count} violations, found {len(result)}"

from ochrona.eval.policy import policy_evaluate


class MockDependencySet:
    def __init__(self, flat_list=[], dependencies=[]):
        self.flat_list = flat_list
        self.dependencies = [MockDependency(**d) for d in dependencies]

class MockDependency:
    def __init__(self, **kwargs):
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

    @staticmethod
    def policy_evaluator_harness(package_list, policies, expected_violation_count):
        """
        Test Harness for running policy evaluation tests.
        """
        result = policy_evaluate(dependencies=package_list, policies=policies)
        assert expected_violation_count == len(
            result
        ), f"Expected {expected_violation_count} violations, found {len(result)}"

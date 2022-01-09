from copy import deepcopy

from ochrona.eval.vuln import evaluate
from ochrona.model.confirmed_vulnerability import Vulnerability

potential_vulnerability = {
                "name": "package_a",
                "owner": "python-requests",
                "repo_url": "http://package_a.com",
                "references": [
                    "https://usn.ubuntu.com/3790-2/",
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
                    "cvss3_score": "9.8",
                },
                "description": "Package_a",
                "language": "python",
                "ochrona_severity_score": "9.8",
                "repository_summary": "Package A",
                "license": "MIT",
                "latest_version": "2.0.0",
                "cve_id": "CVE-2018-18074",
                "publish_date": "2018-10-09T17:29Z",
            }

class TestEvaluator:

    def test_evaluate_no_match_contains_less_than(self):
        """
        Tests evaluation with a contained confirmed match
        """
        package_list = ["package_a==0.0.1", "package_b==1.0.0"]
        potential_vulns = [
            {
                "package_name": "package_b",
                "vulnerabilities": [
                    {"affected_versions": [{"version_value": "1.0.0", "operator": "<"}]}
                ],
            }
        ]
        self.evaluator_harness(package_list, potential_vulns, 0)

    def test_evaluate_no_match_contains(self):
        """
        Tests evaluation with no contained match
        """
        package_list = ["package_a==1.0.1", "package_b==1.0.0"]
        potential_vulns = [
            {
                "package_name": "package_a",
                "vulnerabilities": [
                    {
                        "affected_versions": [
                            {"version_value": "1.0.0", "operator": "<="}
                        ]
                    }
                ],
            }
        ]
        self.evaluator_harness(package_list, potential_vulns, 0)

    def test_evaluate_no_matching_version(self):
        """
        Tests evaluation with no matches
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = deepcopy(potential_vulnerability)
        v["affected_versions"] = [{"version_value": "0.0.1", "operator": "="}]
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)
    
    def test_evaluate_confirmed_match_exact(self):
        """
        Tests evaluation with an exact confirmed match
        """
        package_list = ["package_a==0.0.1", "package_b==1.0.0"]
        v = deepcopy(potential_vulnerability)
        v["affected_versions"] = [{"version_value": "0.0.1", "operator": "="}]
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1, "package_a==0.0.1")

    def test_evaluate_confirmed_match_contains(self):
        """
        Tests evaluation with a contained confirmed match
        """
        package_list = ["package_a==0.0.1", "package_b==1.0.0"]
        v = deepcopy(potential_vulnerability)
        v["affected_versions"] = [{"version_value": "1.0.0", "operator": "<="}]
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1, "package_a==0.0.1")

    def test_evaluate_confirmed_match_contains_less_than(self):
        """
        Tests evaluation with a contained confirmed match
        """
        package_list = ["package_a==0.0.1", "package_b==1.0.0"]
        v = deepcopy(potential_vulnerability)
        v["affected_versions"] = [{"version_value": "1.0.0", "operator": "<"}]
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1, "package_a==0.0.1")

    def test_evaluate_confirmed_match_contains_range(self):
        """
        Tests evaluation with no contained match
        """
        package_list = ["package_a<=1.0.1", "package_b==1.0.0"]
        v = deepcopy(potential_vulnerability)
        v["affected_versions"] = [{"version_value": "1.1.0", "operator": "<"}]
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1, "package_a<=1.0.1")

    def test_evaluate_confirmed_match_any_version_unspecified(self):
        """
        Tests evaluation with no contained match
        """
        package_list = ["package_a==1.0.1", "package_b==1.0.0"]
        v = deepcopy(potential_vulnerability)
        v["affected_versions"] = [{"version_value": "-", "operator": "="}]
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1, "package_a==1.0.1")

    def test_evaluate_confirmed_match_any_version_unspecified_no_version_provided(self):
        """
        Tests evaluation with no contained match
        """
        package_list = ["package_a", "package_b==1.0.0"]
        v = deepcopy(potential_vulnerability)
        v["affected_versions"] = [{"version_value": "-", "operator": "="}]
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1, "package_a")

    def test_evaluate_confirmed_match_non_semvar(self):
        """
        Tests evaluation with no contained match
        """
        package_list = ["package_a==1.0.1.0", "package_b==1.0.0"]
        v = deepcopy(potential_vulnerability)
        v["affected_versions"] = [{"version_value": "1.1.0", "operator": "<"}]
        potential_vulns = [v]
        self.evaluator_harness(
            package_list, potential_vulns, 1, "package_a==1.0.1.0"
        )

    def test_evaluate_expression_equals_any(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version==*"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_equals_true(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version==1.0.0"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_equals_false(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version==0.4.2"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)

    def test_evaluate_expression_nequals_true(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version!=2.1.3"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_nequals_false(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version!=1.0.0"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)

    def test_evaluate_expression_less_than_true(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version<1.2.0"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_less_than_false(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version<0.9.0"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)

    def test_evaluate_expression_less_than_equal_true(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version<=1.2.0"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_less_than_equal_false(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version<=0.9.0"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)
    
    def test_evaluate_expression_greater_than_true(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version>0.0.10"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_greater_than_false(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version>1.2.6"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)

    def test_evaluate_expression_greater_than_equal_true(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version>=0.0.10"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_greater_than_equal_false(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version>=1.2.6"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)

    def test_evaluate_expression_or_true(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version < 0.16.8 OR version < 1.3.7"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_or_false(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version < 0.16.8 OR version > 1.3.2"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)

    def test_evaluate_expression_in_true(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version IN 1.0.0, 1.0.1, 1.0.2"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_in_false(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.0", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version IN 0.1.0, 0.2.0, 0.3.0"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)

    def test_evaluate_expression_between_true(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.0.3", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version >= 1.0.0 AND version < 1.5.3"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_between_false(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.5.4", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "version >= 1.0.0 AND version < 1.5.3"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)

    def test_evaluate_expression_brackets_true(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.5.2", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "(version >= 1.0.0 AND version < 1.5.3) OR (version >= 2.0.0 AND version < 2.3.3)"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 1)

    def test_evaluate_expression_brackets_false(self):
        """
        Tests evaluation with expression
        """
        package_list = ["package_a==1.5.2", "package_b==1.0.0"]
        v = potential_vulnerability
        v["vulnerable_version_expression"] = "(version >= 1.0.0 AND version < 1.5.3) AND (version >= 2.0.0 AND version < 2.3.3)"
        potential_vulns = [v]
        self.evaluator_harness(package_list, potential_vulns, 0)

    @staticmethod
    def evaluator_harness(
        package_list,
        potential_vulns,
        expected_confirmed_count,
        expected_found_version=None,
    ):
        """
        Test Harness for running evaluation tests.
        """
        result = evaluate(potential_vulns, package_list)
        assert (
            len(result) == expected_confirmed_count
        ), "expected {} confirmed vulns".format(expected_confirmed_count)
        if result and expected_found_version is not None:
            assert isinstance(result[0], Vulnerability)
            assert (
                result[0].found_version
                == expected_found_version)

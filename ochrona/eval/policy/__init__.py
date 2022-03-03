from ochrona.eval.policy.evaluate import evaluate


def policy_evaluate(dependencies, policies):
    """
    Evauluates dependencies for policy violations.
    """
    violations = []
    for policy in policies:
        violations += evaluate(dependency_list=dependencies.dependencies, policy=policy)
    return violations

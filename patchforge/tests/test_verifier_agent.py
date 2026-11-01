from patchforge.agents.verifier_agent import VerifierAgent
from patchforge.protocol import Decision, Status, TestResult


def _result(iteration, status, failed=None):
    return TestResult(
        attempt_id="a1",
        iteration=iteration,
        status=status,
        exit_code=0 if status == Status.PASS else 1,
        failed_tests=failed or [],
        stack_trace_summary="boom" if status == Status.FAIL else "",
    )


def test_passing_result_is_accepted():
    reflection = VerifierAgent(max_iterations=3).run(_result(1, Status.PASS))
    assert reflection.decision == Decision.ACCEPT


def test_failing_result_under_cap_retries():
    reflection = VerifierAgent(max_iterations=3).run(
        _result(1, Status.FAIL, failed=["test_x"])
    )
    assert reflection.decision == Decision.RETRY
    assert "test_x" in reflection.reflection  # diagnosis references the actual failure
    assert reflection.carry_forward_context is True


def test_failing_result_at_cap_escalates():
    reflection = VerifierAgent(max_iterations=3).run(_result(3, Status.FAIL))
    assert reflection.decision == Decision.ESCALATE
    assert reflection.carry_forward_context is False


def test_reflection_is_iteration_specific():
    """Two different failures should produce two different diagnoses,
    not a generic canned message -- otherwise the retry loop can't learn."""
    r1 = VerifierAgent(max_iterations=5).run(
        _result(1, Status.FAIL, failed=["test_a"])
    )
    r2 = VerifierAgent(max_iterations=5).run(
        _result(2, Status.FAIL, failed=["test_b"])
    )
    assert "test_a" in r1.reflection
    assert "test_b" in r2.reflection
    assert r1.reflection != r2.reflection

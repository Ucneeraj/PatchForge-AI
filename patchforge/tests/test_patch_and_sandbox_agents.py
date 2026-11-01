from patchforge.agents.patch_generator_agent import PatchGeneratorAgent
from patchforge.agents.sandbox_runner_agent import SandboxRunnerAgent
from patchforge.protocol import Finding, RepairPlan, Status, new_id


def _plan(strategy, snippet, cwe_id="CWE-89"):
    finding = Finding(
        finding_id=new_id("finding"),
        file_path="db.py",
        line_start=8,
        line_end=8,
        cwe_id=cwe_id,
        rule_id="test-rule",
        snippet=snippet,
        severity="high",
    )
    return RepairPlan(attempt_id=new_id("attempt"), finding=finding, strategy=strategy)


REAL_SQL_SNIPPET = 'cursor.execute(f"SELECT * FROM users WHERE name = \'{user}\'")'
REAL_SECRET_SNIPPET = 'password = "hunter2"'


def test_sql_injection_gets_a_real_auto_fix_from_actual_code():
    """The generator must derive the fix from the ACTUAL flagged snippet,
    not return a canned example -- this is what makes it work on an
    arbitrary repo, not just a demo file."""
    plan = _plan("parameterized_query", REAL_SQL_SNIPPET)
    patch = PatchGeneratorAgent().run(plan, iteration=1)

    assert patch.replacement_code is not None
    assert "%s" in patch.replacement_code
    assert "{user}" not in patch.replacement_code  # placeholder actually removed
    assert "(user,)" in patch.replacement_code
    assert patch.new_test_code is not None


def test_hardcoded_secret_gets_a_real_auto_fix():
    plan = _plan("externalize_secret", REAL_SECRET_SNIPPET, cwe_id="CWE-798")
    patch = PatchGeneratorAgent().run(plan, iteration=1)

    assert patch.replacement_code == 'password = os.environ["PASSWORD"]'


def test_unmatched_pattern_is_honestly_reported_as_unfixed():
    """If the snippet doesn't match the expected shape, the generator must
    NOT fabricate a fix -- replacement_code should be None so the sandbox
    correctly fails rather than silently claiming success."""
    plan = _plan("parameterized_query", "cursor.execute(some_dynamic_thing())")
    patch = PatchGeneratorAgent().run(plan, iteration=1)

    assert patch.replacement_code is None
    assert "Could not confidently derive" in patch.rationale


def test_unsupported_strategy_is_honestly_reported_as_unfixed():
    plan = _plan("some_future_strategy", "whatever()")
    patch = PatchGeneratorAgent().run(plan, iteration=1)

    assert patch.replacement_code is None


def test_patch_generator_propagates_location_for_real_application():
    """CandidatePatch must carry enough info (file_path/line range) for a
    sandbox to actually write the fix into a real file."""
    plan = _plan("parameterized_query", REAL_SQL_SNIPPET)
    patch = PatchGeneratorAgent().run(plan, iteration=2)

    assert patch.iteration == 2
    assert patch.file_path == "db.py"
    assert patch.line_start == 8
    assert patch.line_end == 8
    assert patch.finding_id == plan.finding.finding_id


def test_sandbox_mock_fails_first_then_passes_second():
    """Verifies the mock's simulated retry behavior, which the orchestrator
    integration test relies on to exercise the retry path."""
    plan = _plan("parameterized_query", REAL_SQL_SNIPPET)
    patch1 = PatchGeneratorAgent().run(plan, iteration=1)
    patch2 = PatchGeneratorAgent().run(plan, iteration=2)

    runner = SandboxRunnerAgent()
    result1 = runner.run(patch1)
    result2 = runner.run(patch2)

    assert result1.status == Status.FAIL
    assert result2.status == Status.PASS

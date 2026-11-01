"""
Integration test for the Orchestrator: this is the test that actually proves
the "coordination" and "communication protocol" parts of the milestone --
not any single agent in isolation, but the full scan -> plan -> patch ->
sandbox -> reflect -> retry/accept loop wired together correctly.
"""

from patchforge.orchestrator import Orchestrator
from patchforge.protocol import Decision

VULNERABLE_SAMPLE = '''
import os

password = "hunter2"

def run_query(user):
    cursor = get_cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user}'")
    return cursor.fetchall()
'''

CLEAN_SAMPLE = '''
def add(a, b):
    return a + b
'''


def test_clean_file_produces_no_repair_attempts():
    outcomes = Orchestrator().run_file("clean.py", CLEAN_SAMPLE)
    assert outcomes == []


def test_full_pipeline_repairs_both_findings():
    outcomes = Orchestrator(max_iterations=3).run_file("db/queries.py", VULNERABLE_SAMPLE)

    # One outcome per finding: the SQL injection and the hardcoded secret
    assert len(outcomes) == 2
    cwe_ids = {o.finding.cwe_id for o in outcomes}
    assert cwe_ids == {"CWE-89", "CWE-798"}


def test_higher_severity_finding_is_repaired_first():
    outcomes = Orchestrator(max_iterations=3).run_file("db/queries.py", VULNERABLE_SAMPLE)
    # CWE-89 (high) should be planned/repaired before CWE-798 (medium)
    assert outcomes[0].finding.cwe_id == "CWE-89"


def test_successful_outcome_carries_full_audit_trail():
    outcomes = Orchestrator(max_iterations=3).run_file("db/queries.py", VULNERABLE_SAMPLE)
    sql_outcome = next(o for o in outcomes if o.finding.cwe_id == "CWE-89")

    assert sql_outcome.success is True
    assert sql_outcome.final_diff is not None
    assert sql_outcome.test_report is not None
    assert len(sql_outcome.reflections) >= 1
    # The mock sandbox fails iteration 1 then passes iteration 2 --
    # verifying the retry path was actually exercised, not just a
    # first-try pass.
    assert sql_outcome.iterations_used == 2
    assert sql_outcome.reflections[0].decision == Decision.RETRY
    assert sql_outcome.reflections[-1].decision == Decision.ACCEPT


def test_escalation_path_when_iteration_cap_is_too_low():
    """With max_iterations=1, the mock sandbox's first-attempt failure
    can never be retried, so the orchestrator must escalate rather than
    loop forever or silently succeed."""
    outcomes = Orchestrator(max_iterations=1).run_file("db/queries.py", VULNERABLE_SAMPLE)
    sql_outcome = next(o for o in outcomes if o.finding.cwe_id == "CWE-89")

    assert sql_outcome.success is False
    assert sql_outcome.final_diff is None
    assert sql_outcome.reflections[-1].decision == Decision.ESCALATE


def test_outcome_serializes_to_json():
    """The final artifact must be machine-readable (for CI / reporting),
    not just human-printed."""
    outcomes = Orchestrator(max_iterations=3).run_file("db/queries.py", VULNERABLE_SAMPLE)
    payload = outcomes[0].to_json()
    assert '"finding_id"' in payload
    assert '"cwe_id"' in payload

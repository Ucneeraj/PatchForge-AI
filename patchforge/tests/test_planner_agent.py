from patchforge.agents.planner_agent import PlannerAgent
from patchforge.protocol import Finding, new_id


def _finding(cwe_id, severity):
    return Finding(
        finding_id=new_id("finding"),
        file_path="x.py",
        line_start=1,
        line_end=1,
        cwe_id=cwe_id,
        rule_id="test-rule",
        snippet="x = 1",
        severity=severity,
    )


def test_higher_severity_ranked_first():
    findings = [
        _finding("CWE-798", "low"),
        _finding("CWE-89", "high"),
        _finding("CWE-79", "medium"),
    ]
    plans = PlannerAgent().run(findings)
    assert plans[0].finding.severity == "high"
    assert plans[-1].finding.severity == "low"


def test_strategy_selected_by_cwe():
    plans = PlannerAgent().run([_finding("CWE-89", "high")])
    assert plans[0].strategy == "parameterized_query"


def test_unknown_cwe_gets_generic_strategy():
    plans = PlannerAgent().run([_finding("CWE-9999", "medium")])
    assert plans[0].strategy == "generic_llm_patch"


def test_every_plan_gets_a_unique_attempt_id():
    findings = [_finding("CWE-89", "high"), _finding("CWE-89", "high")]
    plans = PlannerAgent().run(findings)
    assert plans[0].attempt_id != plans[1].attempt_id

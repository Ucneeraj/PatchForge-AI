"""
planner_agent.py

Turns raw Findings into prioritized RepairPlans. Priority ordering and
strategy selection are rule-based here (severity + a lookup table per
CWE) -- this keeps planning cheap and auditable; only patch *generation*
needs an LLM.
"""

from __future__ import annotations

from ..protocol import Finding, RepairPlan, new_id
from .base_agent import BaseAgent

_SEVERITY_WEIGHT = {"critical": 3, "high": 2, "medium": 1, "low": 0}

_STRATEGY_BY_CWE = {
    "CWE-89": "parameterized_query",
    "CWE-79": "escape_output",
    "CWE-798": "externalize_secret",
}


class PlannerAgent(BaseAgent):
    name = "planner"

    def run(self, findings: list[Finding]) -> list[RepairPlan]:
        ranked = sorted(
            findings,
            key=lambda f: _SEVERITY_WEIGHT.get(f.severity, 0),
            reverse=True,
        )
        plans = []
        for priority, finding in enumerate(ranked):
            plans.append(
                RepairPlan(
                    attempt_id=new_id("attempt"),
                    finding=finding,
                    strategy=_STRATEGY_BY_CWE.get(finding.cwe_id, "generic_llm_patch"),
                    priority=priority,
                    context_files=[finding.file_path],
                )
            )
        return plans

"""
protocol.py

Defines the strict, typed message contracts agents use to communicate.
No agent passes freeform prose to another agent -- every hand-off is one
of these dataclasses, serialized to/from JSON at the orchestrator boundary.

This is the single most important file in the system: if you change an
agent's internals, nothing else should need to change as long as it still
speaks this protocol.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class Status(str, Enum):
    PENDING = "pending"
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


class Decision(str, Enum):
    RETRY = "retry"
    ESCALATE = "escalate"
    ACCEPT = "accept"


# ---------------------------------------------------------------------------
# Scanner -> Planner
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single vulnerability candidate located by the Scanner agent."""
    finding_id: str
    file_path: str
    line_start: int
    line_end: int
    cwe_id: str
    rule_id: str
    snippet: str
    severity: str = "medium"  # low | medium | high | critical

    def to_json(self) -> str:
        return json.dumps(asdict(self))


# ---------------------------------------------------------------------------
# Planner -> Patch-Generator
# ---------------------------------------------------------------------------

@dataclass
class RepairPlan:
    """One prioritized unit of work handed to the Patch-Generator."""
    attempt_id: str
    finding: Finding
    strategy: str          # e.g. "parameterized_query", "escape_output"
    priority: int = 0
    context_files: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Patch-Generator -> Sandbox-Runner
# ---------------------------------------------------------------------------

@dataclass
class CandidatePatch:
    attempt_id: str
    iteration: int
    finding_id: str
    diff: str               # unified diff text (for human-readable reporting)
    rationale: str          # short explanation of the change
    new_test_code: Optional[str] = None  # regression test to add, if any
    # Fields needed to actually APPLY the fix to a real file on disk,
    # rather than just describing it. `replacement_code` is None when no
    # automatic fix could be derived (unsupported pattern / strategy) --
    # the Sandbox-Runner must not fabricate success in that case.
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    replacement_code: Optional[str] = None


# ---------------------------------------------------------------------------
# Sandbox-Runner -> Verifier/Reflector
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    attempt_id: str
    iteration: int
    status: Status
    exit_code: int
    passed_tests: list = field(default_factory=list)
    failed_tests: list = field(default_factory=list)
    stack_trace_summary: str = ""
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Verifier/Reflector -> Orchestrator (and back to Patch-Generator on retry)
# ---------------------------------------------------------------------------

@dataclass
class ReflectionResult:
    attempt_id: str
    iteration: int
    decision: Decision
    reflection: str          # persistent, human-readable diagnosis of *why*
    carry_forward_context: bool = True


# ---------------------------------------------------------------------------
# Final artifact produced by the Orchestrator
# ---------------------------------------------------------------------------

@dataclass
class RepairOutcome:
    attempt_id: str
    finding: Finding
    success: bool
    iterations_used: int
    final_diff: Optional[str] = None
    test_report: Optional[TestResult] = None
    reflections: list = field(default_factory=list)  # audit trail

    def to_json(self, indent: int = 2) -> str:
        d = asdict(self)
        return json.dumps(d, indent=indent, default=str)


# ---------------------------------------------------------------------------
# Orchestrator -> caller, whole-repo run (repo ingestion feature)
# ---------------------------------------------------------------------------

@dataclass
class RepoScanReport:
    """Top-level result of running the pipeline over an entire repo."""
    source: str                      # the GitHub URL or local path given
    files_scanned: int
    skipped_languages: dict          # {extension: count} not scanned this run
    outcomes: list                   # list[RepairOutcome], across all files
    corrected_clone_path: str = ""   # where the corrected copy of the repo lives on disk
    scan_errors: dict = field(default_factory=dict)  # {file_path: error message} for files that couldn't be scanned

    @property
    def total_findings(self) -> int:
        return len(self.outcomes)

    @property
    def total_repaired(self) -> int:
        return sum(1 for o in self.outcomes if o.success)

    @property
    def total_escalated(self) -> int:
        return sum(1 for o in self.outcomes if not o.success)

    def to_json(self, indent: int = 2) -> str:
        d = {
            "source": self.source,
            "files_scanned": self.files_scanned,
            "skipped_languages": self.skipped_languages,
            "corrected_clone_path": self.corrected_clone_path,
            "total_findings": self.total_findings,
            "total_repaired": self.total_repaired,
            "total_escalated": self.total_escalated,
            "scan_errors": self.scan_errors,
            "outcomes": [asdict(o) for o in self.outcomes],
        }
        return json.dumps(d, indent=indent, default=str)

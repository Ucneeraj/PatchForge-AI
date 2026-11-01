"""
orchestrator.py

Owns the state machine described in the architecture doc:

    Scan -> Plan -> Generate Patch -> Sandbox Test -> (pass -> Finalize)
                          ^                  |
                          |            fail  v
                          +---- Reflect + Retry
                                     |
                        (max iterations) -> Escalate

The Orchestrator does not itself decide *how* to patch or *why* a patch
failed -- it only sequences the specialist agents and enforces the
system-level bounds (NFR2 timeouts are enforced inside the sandbox
backend; NFR5 iteration/token caps are enforced here).
"""

from __future__ import annotations

import shutil

from .agents.patch_generator_agent import PatchGeneratorAgent
from .agents.planner_agent import PlannerAgent
from .agents.repo_ingestion_agent import RepoIngestionAgent
from .agents.sandbox_runner_agent import LocalSandboxBackend, SandboxRunnerAgent
from .agents.scanner_agent import ScannerAgent
from .agents.verifier_agent import VerifierAgent
from .protocol import Decision, RepairOutcome, RepoScanReport


class Orchestrator:
    def __init__(
        self,
        scanner: ScannerAgent | None = None,
        planner: PlannerAgent | None = None,
        patch_generator: PatchGeneratorAgent | None = None,
        sandbox_runner: SandboxRunnerAgent | None = None,
        verifier: VerifierAgent | None = None,
        repo_ingestion: RepoIngestionAgent | None = None,
        max_iterations: int = 3,
    ):
        self.scanner = scanner or ScannerAgent()
        self.planner = planner or PlannerAgent()
        self.patch_generator = patch_generator or PatchGeneratorAgent()
        self.sandbox_runner = sandbox_runner or SandboxRunnerAgent()
        self.verifier = verifier or VerifierAgent(max_iterations=max_iterations)
        self.repo_ingestion = repo_ingestion or RepoIngestionAgent()
        self.max_iterations = max_iterations

    def run_repo(self, source: str, workdir: str | None = None) -> RepoScanReport:
        """
        Entry point for the "give it a GitHub link" use case. Clones (or
        opens, if given a local path) the repo, makes a disposable
        working copy of it (the "corrected clone" -- the original is
        never touched), scans every file in the currently-supported
        languages (Python only for now), and runs each finding through
        the full repair loop against REAL code -- applying real fixes
        and running real tests inside the corrected clone. Returns one
        aggregated report, including where the corrected clone lives on
        disk.
        """
        context = self.repo_ingestion.timed_run("ingest", source, workdir)

        corrected_root = context.local_path.rstrip("/\\") + "_corrected"
        shutil.rmtree(corrected_root, ignore_errors=True)
        shutil.copytree(context.local_path, corrected_root)

        # Swap in the real local sandbox for the duration of this repo
        # run, then restore whatever backend was configured before --
        # run_file()/the single-file demo keep using their own default.
        original_sandbox_runner = self.sandbox_runner
        self.sandbox_runner = SandboxRunnerAgent(
            backend=LocalSandboxBackend(corrected_root)
        )
        try:
            all_outcomes: list[RepairOutcome] = []
            scan_errors: dict[str, str] = {}
            for source_file in context.files:
                try:
                    with open(source_file.absolute_path, "r", encoding="utf-8") as f:
                        file_source = f.read()
                    outcomes = self.run_file(source_file.path, file_source)
                    all_outcomes.extend(outcomes)
                except (SyntaxError, UnicodeDecodeError) as e:
                    # A single broken/unparseable file (invalid syntax,
                    # bad encoding, generated/binary-ish content, etc.)
                    # must not take down the whole repo scan -- record
                    # it honestly and keep going.
                    scan_errors[source_file.path] = f"{type(e).__name__}: {e}"
                    self.scanner._log("scan", f"skipping {source_file.path}: {e}")
        finally:
            self.sandbox_runner = original_sandbox_runner

        return RepoScanReport(
            source=source,
            files_scanned=len(context.files),
            skipped_languages=context.skipped_languages,
            outcomes=all_outcomes,
            corrected_clone_path=corrected_root,
            scan_errors=scan_errors,
        )

    def run_file(self, file_path: str, source: str) -> list[RepairOutcome]:
        """Full pipeline: scan a file, then attempt to repair every finding."""
        findings = self.scanner.timed_run("scan", file_path, source)
        if not findings:
            return []

        plans = self.planner.run(findings)
        return [self._repair_one(plan) for plan in plans]

    def _repair_one(self, plan) -> RepairOutcome:
        attempt_id = plan.attempt_id
        reflections = []
        prior_reflection = None
        iteration = 1

        while True:
            patch = self.patch_generator.timed_run(
                attempt_id, plan, iteration, prior_reflection
            )
            result = self.sandbox_runner.timed_run(attempt_id, patch)
            reflection = self.verifier.timed_run(attempt_id, result)
            reflections.append(reflection)

            if reflection.decision == Decision.ACCEPT:
                return RepairOutcome(
                    attempt_id=attempt_id,
                    finding=plan.finding,
                    success=True,
                    iterations_used=iteration,
                    final_diff=patch.diff,
                    test_report=result,
                    reflections=reflections,
                )

            if reflection.decision == Decision.ESCALATE:
                return RepairOutcome(
                    attempt_id=attempt_id,
                    finding=plan.finding,
                    success=False,
                    iterations_used=iteration,
                    final_diff=None,
                    test_report=result,
                    reflections=reflections,
                )

            # RETRY: carry the reflection forward and loop
            prior_reflection = reflection.reflection
            iteration += 1

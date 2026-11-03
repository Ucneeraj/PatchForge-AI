"""
orchestrator.py

Owns the state machine described in the architecture doc:

    Scan -> Plan -> Generate Patch -> Sandbox Test -> (pass -> Finalize)
                          ^                  |
                          |            fail  v
                          +---- Reflect + Retry
                                     |
                        (max iterations) -> Escalate

The Orchestrator sequences specialist agents and enforces system-level bounds.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from agents.patch_generator_agent import PatchGeneratorAgent, OpenAIPatchClient
from agents.planner_agent import PlannerAgent
from agents.repo_ingestion_agent import RepoIngestionAgent
from agents.sandbox_runner_agent import LocalSandboxBackend, SandboxRunnerAgent, DockerSandboxBackend
from agents.scanner_agent import ScannerAgent
from agents.verifier_agent import VerifierAgent
from protocol import Decision, RepairOutcome, RepoScanReport


def get_safe_sandbox_backend(workdir: str):
    """
    Attempts to initialize Docker. If Docker daemon is unavailable
    (e.g., inside Streamlit Cloud), falls back to LocalSandboxBackend.
    """
    try:
        return DockerSandboxBackend()
    except Exception as e:
        print(f"Docker socket unavailable ({e}). Falling back to LocalSandboxBackend.")
        return LocalSandboxBackend(corrected_clone_root=workdir)


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
        Entry point for repository scanning and remediation.
        Clones or opens the repo, creates a disposable working copy,
        scans all Python files, and executes the patch-test loop for any findings.
        """
        context = self.repo_ingestion.timed_run("ingest", source, workdir)

        # Create corrected clone root directory
        corrected_root = context.local_path.rstrip("/\\") + "_corrected"
        shutil.rmtree(corrected_root, ignore_errors=True)
        shutil.copytree(context.local_path, corrected_root)

        original_sandbox_runner = self.sandbox_runner
        original_patch_generator = self.patch_generator

        # Dynamically set sandbox runner (Docker if available, otherwise local process fallback)
        safe_backend = get_safe_sandbox_backend(corrected_root)
        self.sandbox_runner = SandboxRunnerAgent(backend=safe_backend)
        self.patch_generator = PatchGeneratorAgent(llm_client=OpenAIPatchClient())
        
        all_outcomes: list[RepairOutcome] = []
        scan_errors: dict[str, str] = {}
        files_count = 0

        try:
            # Fallback file discovery if context.files is empty or unpopulated
            root_path = Path(context.local_path)
            py_files = list(root_path.rglob("*.py"))
            
            # Filter out virtualenvs, git, build artifacts
            py_files = [
                p for p in py_files
                if not any(ignored in p.parts for ignored in [".git", "venv", ".venv", "__pycache__", "build", "dist"])
            ]
            files_count = len(py_files)

            for p in py_files:
                rel_path = str(p.relative_to(root_path))
                try:
                    file_source = p.read_text(encoding="utf-8", errors="ignore")
                    outcomes = self.run_file(rel_path, file_source, corrected_root)
                    all_outcomes.extend(outcomes)
                except Exception as e:
                    scan_errors[rel_path] = f"{type(e).__name__}: {e}"
                    if hasattr(self.scanner, "_log"):
                        self.scanner._log("scan", f"skipping {rel_path}: {e}")

        finally:
            # Restore original backends
            self.sandbox_runner = original_sandbox_runner
            self.patch_generator = original_patch_generator

        return RepoScanReport(
            source=source,
            files_scanned=files_count,
            skipped_languages=getattr(context, "skipped_languages", {}),
            outcomes=all_outcomes,
            corrected_clone_path=corrected_root,
            scan_errors=scan_errors,
        )

    def run_file(self, file_path: str, source: str, corrected_root: str | None = None) -> list[RepairOutcome]:
        """Full pipeline: scan a file, then attempt to repair every finding."""
        findings = self.scanner.timed_run("scan", file_path, source)
        if not findings:
            return []

        plans = self.planner.run(findings)
        return [self._repair_one(plan, corrected_root) for plan in plans]

    def _repair_one(self, plan, corrected_root: str | None = None) -> RepairOutcome:
        attempt_id = plan.attempt_id
        reflections = []
        prior_reflection = None
        iteration = 1

        while True:
            patch = self.patch_generator.timed_run(
                attempt_id, plan, iteration, prior_reflection
            )
            
            # Attach corrected_clone_path so DockerSandboxBackend knows which directory to mount
            if corrected_root:
                setattr(patch, "corrected_clone_path", corrected_root)

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

            if reflection.decision == Decision.ESCALATE or iteration >= self.max_iterations:
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
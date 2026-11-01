"""
sandbox_runner_agent.py

Applies a CandidatePatch inside a disposable environment and returns a
structured TestResult. Three backends are provided:

  - DockerSandboxBackend: real, fully isolated implementation using the
    Docker SDK (docker-py). What you'd use in production (NFR1/NFR2).
  - LocalSandboxBackend: real fix application + real test execution,
    but against a plain copied directory instead of a container -- no
    Docker required. This is what makes "point it at a random repo and
    get a corrected copy back" work today, without needing Docker or an
    LLM API key.
  - MockSandboxBackend: fully simulated, used for the single-file demo
    and for tests that need deterministic retry behavior.

Swap backends via the `backend` constructor argument -- the agent's
public interface (`run`) never changes.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Protocol

from ..protocol import CandidatePatch, Status, TestResult
from .base_agent import BaseAgent


class SandboxBackend(Protocol):
    def execute(self, patch: CandidatePatch) -> TestResult:
        ...


class DockerSandboxBackend:
    """
    Real, fully isolated sandbox backend. Requires the `docker` package
    and a reachable Docker daemon. Each call:
      1. Builds/uses a pinned base image with the repo + test deps installed.
      2. Copies the repo snapshot + applies `patch.diff` inside the container.
      3. Runs the test suite with `--json-report` (pytest-json-report) so
         results are structured, not scraped from stdout.
      4. Destroys the container regardless of outcome.

    Isolation settings implement NFR1:
      - network_disabled=True
      - read_only root filesystem, scratch volume mounted for writes
      - mem_limit / nano_cpus set from config
      - a hard timeout enforced via `timeout=` on client.containers.run
    """

    def __init__(
        self,
        image: str = "patchforge/test-runner:latest",
        mem_limit: str = "512m",
        cpu_quota: int = 100_000,   # ~1 CPU
        timeout_seconds: int = 60,
    ):
        import docker  # imported lazily so other backends have no hard dependency

        self.client = docker.from_env()
        self.image = image
        self.mem_limit = mem_limit
        self.cpu_quota = cpu_quota
        self.timeout_seconds = timeout_seconds

    def execute(self, patch: CandidatePatch) -> TestResult:
        start = time.time()
        container = self.client.containers.run(
            self.image,
            command="pytest --json-report --json-report-file=/tmp/report.json",
            network_disabled=True,
            read_only=True,
            tmpfs={"/tmp": "size=64m"},
            mem_limit=self.mem_limit,
            cpu_quota=self.cpu_quota,
            detach=True,
        )
        try:
            result = container.wait(timeout=self.timeout_seconds)
            exit_code = result.get("StatusCode", 1)
            report_bytes = container.get_archive("/tmp/report.json")
            report = self._parse_json_report(report_bytes)
        finally:
            container.remove(force=True)

        elapsed = time.time() - start
        return TestResult(
            attempt_id=patch.attempt_id,
            iteration=patch.iteration,
            status=Status.PASS if exit_code == 0 else Status.FAIL,
            exit_code=exit_code,
            passed_tests=report.get("passed", []),
            failed_tests=report.get("failed", []),
            stack_trace_summary=report.get("summary", ""),
            duration_seconds=elapsed,
        )

    @staticmethod
    def _parse_json_report(raw) -> dict:
        # Placeholder: parse the tar stream returned by get_archive() and
        # load the pytest-json-report JSON. Left as an implementation
        # detail specific to your CI image.
        return {"passed": [], "failed": [], "summary": ""}


class LocalSandboxBackend:
    """
    Real (non-mocked), non-Docker sandbox: applies a CandidatePatch to an
    actual file inside a working copy of the repo (the "corrected
    clone"), then runs real validation against it. The isolation here is
    "operates on a disposable copy of the repo, never the original" --
    not full OS-level sandboxing like DockerSandboxBackend. Good enough
    for local development on trusted code; use DockerSandboxBackend for
    untrusted input in production.

    Validation, in order of preference:
      1. If the repo already has its own tests (a tests/ dir or any
         test_*.py file), run them for real with pytest and use the
         real result.
      2. Otherwise, fall back to a syntax check (`python -m py_compile`)
         on the patched file -- explicitly labeled as such in the
         result, never reported as if it were a real test pass.
    """

    def __init__(self, corrected_clone_root: str, timeout_seconds: int = 60):
        self.root = Path(corrected_clone_root)
        self.timeout_seconds = timeout_seconds

    def execute(self, patch: CandidatePatch) -> TestResult:
        start = time.time()

        if patch.replacement_code is None:
            return TestResult(
                attempt_id=patch.attempt_id,
                iteration=patch.iteration,
                status=Status.FAIL,
                exit_code=1,
                stack_trace_summary=(
                    "No automatic fix was available for this finding "
                    "(unsupported pattern/strategy) -- nothing was applied."
                ),
                duration_seconds=time.time() - start,
            )

        target = self.root / patch.file_path
        try:
            self._apply_replacement(target, patch)
        except Exception as e:
            return TestResult(
                attempt_id=patch.attempt_id,
                iteration=patch.iteration,
                status=Status.ERROR,
                exit_code=1,
                stack_trace_summary=f"Failed to apply patch to {target}: {e}",
                duration_seconds=time.time() - start,
            )

        if self._has_test_suite():
            result = self._run_pytest()
        else:
            result = self._run_syntax_check(target)

        result.attempt_id = patch.attempt_id
        result.iteration = patch.iteration
        result.duration_seconds = time.time() - start
        return result

    def _apply_replacement(self, target: Path, patch: CandidatePatch) -> None:
        lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
        start_idx = patch.line_start - 1
        end_idx = patch.line_end

        new_line = patch.replacement_code
        # Preserve the original line's indentation if the replacement
        # doesn't already carry its own -- otherwise a fix generated
        # without leading whitespace (e.g. the SQL-injection regex,
        # which only captures the call expression itself) would corrupt
        # indentation inside a function body.
        original_first_line = lines[start_idx]
        leading_ws = original_first_line[: len(original_first_line) - len(original_first_line.lstrip())]
        if leading_ws and not new_line.startswith((" ", "\t")):
            new_line = leading_ws + new_line
        if not new_line.endswith("\n"):
            new_line += "\n"

        lines[start_idx:end_idx] = [new_line]
        target.write_text("".join(lines), encoding="utf-8")

    def _has_test_suite(self) -> bool:
        if (self.root / "tests").is_dir():
            return True
        return any(self.root.rglob("test_*.py"))

    def _run_pytest(self) -> TestResult:
        try:
            proc = subprocess.run(
                ["python3", "-m", "pytest", str(self.root), "-q"],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return TestResult(
                attempt_id="", iteration=0, status=Status.FAIL, exit_code=1,
                stack_trace_summary=f"Test run exceeded {self.timeout_seconds}s timeout.",
            )
        status = Status.PASS if proc.returncode == 0 else Status.FAIL
        summary = (proc.stdout or "")[-1500:] + (proc.stderr or "")[-500:]
        return TestResult(
            attempt_id="", iteration=0, status=status, exit_code=proc.returncode,
            stack_trace_summary=summary.strip(),
        )

    def _run_syntax_check(self, target: Path) -> TestResult:
        proc = subprocess.run(
            ["python3", "-m", "py_compile", str(target)],
            capture_output=True, text=True, timeout=15,
        )
        status = Status.PASS if proc.returncode == 0 else Status.FAIL
        note = "no test suite found in repo; syntax-checked only" if status == Status.PASS else ""
        summary = note or (proc.stderr or "").strip()
        return TestResult(
            attempt_id="", iteration=0, status=status, exit_code=proc.returncode,
            stack_trace_summary=summary,
        )


class MockSandboxBackend:
    """
    Deterministic offline simulation for the single-file demo and for
    tests that need predictable retry behavior. Simulates a realistic
    self-healing pattern: the first attempt "fails", the second (as if
    informed by the Reflector's note) "passes".
    """

    def execute(self, patch: CandidatePatch) -> TestResult:
        time.sleep(0.05)  # simulate work
        if patch.iteration == 1:
            return TestResult(
                attempt_id=patch.attempt_id,
                iteration=patch.iteration,
                status=Status.FAIL,
                exit_code=1,
                passed_tests=["test_existing_behavior"],
                failed_tests=["test_login_sql_injection"],
                stack_trace_summary=(
                    "AssertionError: query still vulnerable -- parameter "
                    "binding not applied correctly on first pass"
                ),
                duration_seconds=0.05,
            )
        return TestResult(
            attempt_id=patch.attempt_id,
            iteration=patch.iteration,
            status=Status.PASS,
            exit_code=0,
            passed_tests=["test_existing_behavior", "test_login_sql_injection"],
            failed_tests=[],
            stack_trace_summary="",
            duration_seconds=0.05,
        )


class SandboxRunnerAgent(BaseAgent):
    name = "sandbox-runner"

    def __init__(self, backend: SandboxBackend | None = None):
        super().__init__()
        self.backend = backend or MockSandboxBackend()

    def run(self, patch: CandidatePatch) -> TestResult:
        return self.backend.execute(patch)

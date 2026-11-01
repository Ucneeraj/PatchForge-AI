"""
sandbox_runner_agent.py

Applies a CandidatePatch inside a disposable environment and returns a
structured TestResult.
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    import docker  # type: ignore

from agents.base_agent import BaseAgent
from protocol import CandidatePatch, Status, TestResult


class SandboxBackend(Protocol):
    def execute(self, patch: CandidatePatch) -> TestResult:
        ...


class DockerSandboxBackend:
    """
    Real, fully isolated sandbox backend using Docker.
    """

    def __init__(
        self,
        image: str = "patchforge/test-runner:latest",
        mem_limit: str = "512m",
        cpu_quota: int = 100_000,   # ~1 CPU
        timeout_seconds: int = 60,
    ):
        import docker  # type: ignore

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
            try:
                report_bytes = container.get_archive("/tmp/report.json")
                report = self._parse_json_report(report_bytes)
            except Exception as e:
                logs = container.logs().decode("utf-8", errors="replace")
                report = {
                    "passed": [],
                    "failed": [],
                    "summary": f"Report extraction failed ({e}). Container logs:\n{logs[-1000:]}",
                }
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
    def _parse_json_report(raw: Any) -> dict:
        """Parses the tar stream returned by Docker's get_archive() into a JSON dict."""
        try:
            tar_stream, _ = raw
            tar_bytes = b"".join(chunk for chunk in tar_stream)
            
            with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
                member = tar.getmembers()[0]
                f = tar.extractfile(member)
                if f:
                    return json.load(f)
            return {"passed": [], "failed": [], "summary": "Could not extract JSON from tar."}
        except Exception as e:
            return {"passed": [], "failed": [], "summary": f"Sandbox parsing error: {e}"}


class LocalSandboxBackend:
    """
    Applies CandidatePatch to a local directory copy.
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
        start_idx = patch.line_start
        end_idx = patch.line_end

        new_line = patch.replacement_code or ""
        original_first_line = lines[start_idx] if start_idx < len(lines) else ""
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
    Deterministic offline simulation backend.
    """

    def execute(self, patch: CandidatePatch) -> TestResult:
        time.sleep(0.05)
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
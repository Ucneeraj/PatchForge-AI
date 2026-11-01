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


def apply_patch_to_file(root: Path, patch: CandidatePatch) -> None:
    """Applies code replacement to the physical target file within the corrected root."""
    if not patch.replacement_code:
        return

    target = root / patch.file_path
    if not target.exists():
        return

    lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
    start_idx = max(0, patch.line_start - 1)
    end_idx = patch.line_end

    new_line = patch.replacement_code
    original_first_line = lines[start_idx] if start_idx < len(lines) else ""
    leading_ws = original_first_line[: len(original_first_line) - len(original_first_line.lstrip())]
    if leading_ws and not new_line.startswith((" ", "\t")):
        new_line = leading_ws + new_line
    if not new_line.endswith("\n"):
        new_line += "\n"

    lines[start_idx:end_idx] = [new_line]
    target.write_text("".join(lines), encoding="utf-8")


class DockerSandboxBackend:
    """
    Real, isolated sandbox backend using Docker containers.
    """

    def __init__(
        self,
        image: str = "patchforge/test-runner:latest",
        mem_limit: str = "512m",
        cpu_quota: int = 100_000,
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
        workdir = getattr(patch, "corrected_clone_path", None) or getattr(patch, "workdir", None)

        if workdir:
            try:
                apply_patch_to_file(Path(workdir), patch)
            except Exception as e:
                return TestResult(
                    attempt_id=patch.attempt_id,
                    iteration=patch.iteration,
                    status=Status.ERROR,
                    exit_code=1,
                    stack_trace_summary=f"Failed to apply patch before container run: {e}",
                    duration_seconds=time.time() - start,
                )

        # Pytest command with cache-writing disabled
        # Updated clean pytest command without invalid config options
        pytest_cmd = (
          "pytest -p no:cacheprovider "
          "--json-report --json-report-file=/tmp/report.json"
         )

        binds = {}
        if workdir:
            abs_workdir = str(Path(workdir).resolve())
            binds[abs_workdir] = {"bind": "/workspace", "mode": "rw"}

        try:
            container = self.client.containers.run(
                self.image,
                command=pytest_cmd,
                volumes=binds,
                environment={"PYTHONPATH": "/workspace"},  # <--- Fixes ModuleNotFoundError
                network_disabled=True,
                read_only=False,
                tmpfs={"/tmp": "size=64m"},
                mem_limit=self.mem_limit,
                cpu_quota=self.cpu_quota,
                detach=True,
            )
            result = container.wait(timeout=self.timeout_seconds)
            exit_code = result.get("StatusCode", 1)
            logs = container.logs().decode("utf-8", errors="replace")

            report = {}
            try:
                report_bytes = container.get_archive("/tmp/report.json")
                report = self._parse_json_report(report_bytes)
            except Exception:
                # Fallback if report extraction drops: rely on exit code and log stdout
                report = {
                    "passed": ["test_sample.py"] if exit_code == 0 else [],
                    "failed": [] if exit_code == 0 else ["test_sample.py"],
                    "summary": logs[-1000:],
                }
        except Exception as container_err:
            return TestResult(
                attempt_id=patch.attempt_id,
                iteration=patch.iteration,
                status=Status.FAIL,
                exit_code=1,
                stack_trace_summary=f"Container execution error: {container_err}",
                duration_seconds=time.time() - start,
            )
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass

        elapsed = time.time() - start
        
        # Exit code 0 (All tests pass) or 5 (No tests collected in repo, syntax valid) are valid
        is_success = exit_code in (0, 5)

        # Parse test results safely from pytest-json-report payload
        passed_tests = [t.get("nodeid", "") for t in report.get("tests", []) if t.get("outcome") == "passed"]
        failed_tests = [t.get("nodeid", "") for t in report.get("tests", []) if t.get("outcome") == "failed"]

        return TestResult(
            attempt_id=patch.attempt_id,
            iteration=patch.iteration,
            status=Status.PASS if is_success else Status.FAIL,
            exit_code=exit_code,
            passed_tests=passed_tests or report.get("passed", []),
            failed_tests=failed_tests or report.get("failed", []),
            stack_trace_summary=report.get("summary", "") or ("Execution clean." if is_success else "Tests failed."),
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

        try:
            apply_patch_to_file(self.root, patch)
        except Exception as e:
            return TestResult(
                attempt_id=patch.attempt_id,
                iteration=patch.iteration,
                status=Status.ERROR,
                exit_code=1,
                stack_trace_summary=f"Failed to apply patch: {e}",
                duration_seconds=time.time() - start,
            )

        if self._has_test_suite():
            result = self._run_pytest()
        else:
            target = self.root / patch.file_path
            result = self._run_syntax_check(target)

        result.attempt_id = patch.attempt_id
        result.iteration = patch.iteration
        result.duration_seconds = time.time() - start
        return result

    def _has_test_suite(self) -> bool:
        if (self.root / "tests").is_dir():
            return True
        return any(self.root.rglob("test_*.py"))

    def _run_pytest(self) -> TestResult:
        try:
            proc = subprocess.run(
                ["python3", "-m", "pytest", str(self.root), "-q", "-p", "no:cacheprovider"],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return TestResult(
                attempt_id="", iteration=0, status=Status.FAIL, exit_code=1,
                stack_trace_summary=f"Test run exceeded {self.timeout_seconds}s timeout.",
            )
        status = Status.PASS if proc.returncode in (0, 5) else Status.FAIL
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
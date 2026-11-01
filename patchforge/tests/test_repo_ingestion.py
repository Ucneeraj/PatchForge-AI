"""
Tests for RepoIngestionAgent and Orchestrator.run_repo. Uses local
directories rather than real GitHub URLs so the suite runs offline and
deterministically -- RepoIngestionAgent treats any non-URL string as an
already-available local path, which is the same code path a clone
lands in once git has finished, so this exercises the real logic.
"""

import os
import tempfile
from pathlib import Path

from patchforge.agents.repo_ingestion_agent import RepoIngestionAgent
from patchforge.orchestrator import Orchestrator


def _make_repo(tmp_path: Path) -> str:
    """Builds a small fake repo: one vulnerable Python file, one clean
    Python file, one JS file (should be skipped, not scanned), and an
    ignored directory that must not be walked."""
    os.makedirs(tmp_path / "src")
    os.makedirs(tmp_path / "node_modules" / "somepkg")

    (tmp_path / "src" / "db.py").write_text(
        "def run_query(user):\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE name = '{user}'\")\n"
    )
    (tmp_path / "src" / "utils.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "src" / "widget.js").write_text("console.log('hello');\n")
    # This should never be discovered -- ignored directory
    (tmp_path / "node_modules" / "somepkg" / "index.js").write_text("module.exports = {};\n")

    return str(tmp_path)


def test_ingestion_discovers_only_python_files():
    with tempfile.TemporaryDirectory() as tmp:
        repo_path = _make_repo(Path(tmp))
        context = RepoIngestionAgent().run(repo_path)

        discovered = {f.path for f in context.files}
        assert discovered == {"src/db.py", "src/utils.py"}
        assert all(f.language == "python" for f in context.files)


def test_ingestion_ignores_node_modules():
    with tempfile.TemporaryDirectory() as tmp:
        repo_path = _make_repo(Path(tmp))
        context = RepoIngestionAgent().run(repo_path)
        assert not any("node_modules" in f.path for f in context.files)


def test_ingestion_counts_skipped_languages():
    with tempfile.TemporaryDirectory() as tmp:
        repo_path = _make_repo(Path(tmp))
        context = RepoIngestionAgent().run(repo_path)
        # widget.js is a recognized-but-unsupported language; the
        # node_modules JS file is ignored entirely (different reason,
        # not counted as "skipped" -- it's excluded, not out of scope)
        assert context.skipped_languages.get(".js") == 1


def test_url_detection():
    agent = RepoIngestionAgent()
    assert agent._looks_like_git_url("https://github.com/example/repo") is True
    assert agent._looks_like_git_url("git@github.com:example/repo.git") is True
    assert agent._looks_like_git_url("/local/path/to/repo") is False


def test_orchestrator_run_repo_scans_and_repairs_across_files():
    with tempfile.TemporaryDirectory() as tmp:
        repo_path = _make_repo(Path(tmp))
        report = Orchestrator(max_iterations=3).run_repo(repo_path)

        assert report.files_scanned == 2  # db.py and utils.py
        assert report.total_findings == 1  # only db.py has a vulnerability
        assert report.total_repaired == 1
        assert report.outcomes[0].finding.file_path == "src/db.py"
        assert report.skipped_languages.get(".js") == 1


def test_repo_scan_report_serializes_to_json():
    with tempfile.TemporaryDirectory() as tmp:
        repo_path = _make_repo(Path(tmp))
        report = Orchestrator(max_iterations=3).run_repo(repo_path)
        payload = report.to_json()
        assert '"files_scanned"' in payload
        assert '"total_findings"' in payload


def test_unparseable_file_does_not_crash_the_whole_repo_scan():
    """Reproduces a real crash: a repo containing one file with invalid
    Python syntax must not take down the entire scan -- it should be
    skipped and reported, while other files still get processed."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "good.py").write_text('password = "hunter2"\n')
        (tmp_path / "broken.py").write_text("Create 2D array\nx = 1\n")

        report = Orchestrator(max_iterations=3).run_repo(str(tmp_path))

        assert report.files_scanned == 2
        assert "broken.py" in report.scan_errors
        assert "SyntaxError" in report.scan_errors["broken.py"]
        # good.py must still have been scanned and repaired despite
        # broken.py's failure
        assert report.total_findings == 1
        assert report.outcomes[0].finding.file_path == "good.py"

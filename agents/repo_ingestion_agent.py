"""
repo_ingestion_agent.py

Turns a GitHub URL (or a local path, useful for offline testing) into a
list of source files ready for the Scanner. This is the piece that makes
the system take "a GitHub link" as input instead of a single source
string handed to it directly.

Deliberately scoped to Python only for now (LANGUAGE_EXTENSIONS has one
entry) -- see the module docstring at the bottom for exactly what needs
to change to add a language, so extending this later doesn't mean a
redesign.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from agents.base_agent import BaseAgent

# Language scoping lives here, in exactly one place. Adding a language
# later means: (1) add its extension(s) here, (2) give the Scanner a
# rule set that knows how to parse that language. Nothing else in the
# pipeline (Orchestrator, protocol, Planner, etc.) needs to change.
LANGUAGE_EXTENSIONS = {
    ".py": "python",
}

# Directories that are never worth scanning -- dependency trees,
# version control internals, build artifacts, virtualenvs.
IGNORED_DIRS = {
    ".git", "__pycache__", "node_modules", "venv", ".venv", "env",
    "dist", "build", ".tox", ".pytest_cache", "site-packages", "egg-info",
}


@dataclass
class SourceFile:
    """One file discovered in the repo, ready to hand to the Scanner."""
    path: str          # path relative to repo root, used for reporting
    absolute_path: str  # path on disk, used to actually read the file
    language: str


@dataclass
class RepoContext:
    """The result of ingesting a repo: where it lives on disk, and what's in it."""
    source: str                 # the original GitHub URL or local path given
    local_path: str             # where the repo actually sits on disk now
    files: list[SourceFile]
    skipped_languages: dict     # {extension: count} for files found but not scanned


class RepoIngestionAgent(BaseAgent):
    name = "repo-ingestion"

    def run(self, source: str, workdir: str | None = None) -> RepoContext:
        """
        `source` is either a GitHub URL (https://github.com/...) or a
        local directory path (for offline testing / already-cloned repos).
        """
        if self._looks_like_git_url(source):
            local_path = self._clone(source, workdir)
        else:
            local_path = source

        files, skipped = self._discover_files(local_path)
        return RepoContext(
            source=source,
            local_path=local_path,
            files=files,
            skipped_languages=skipped,
        )

    @staticmethod
    def _looks_like_git_url(source: str) -> bool:
        return source.startswith("http://") or source.startswith("https://") or source.endswith(".git")

    def _clone(self, repo_url: str, target_dir: str) -> str:
        import subprocess
        from pathlib import Path
    
        cmd = ["git", "clone", repo_url, target_dir]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
         raise RuntimeError(f"Git clone failed: {res.stderr}")
        return target_dir

    def _discover_files(self, root: str) -> tuple[list[SourceFile], dict]:
        root_path = Path(root)
        files: list[SourceFile] = []
        skipped: dict = {}

        for path in root_path.rglob("*"):
            if not path.is_file():
                continue
            if any(part in IGNORED_DIRS for part in path.parts):
                continue

            ext = path.suffix
            if ext in LANGUAGE_EXTENSIONS:
                files.append(SourceFile(
                    path=str(path.relative_to(root_path)),
                    absolute_path=str(path),
                    language=LANGUAGE_EXTENSIONS[ext],
                ))
            elif ext in (".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php"):
                # Recognized as code, but out of scope for now -- counted
                # so the report can honestly say "N files were not scanned",
                # rather than silently ignoring them.
                skipped[ext] = skipped.get(ext, 0) + 1

        return files, skipped


"""
Adding a new language later:
  1. Add its extension(s) to LANGUAGE_EXTENSIONS above.
  2. Give ScannerAgent a rule set for that language (e.g. a tree-sitter
     grammar + equivalent _rule_* functions to the ones in
     scanner_agent.py, keyed by language).
  3. Nothing in RepoContext, Orchestrator, or the protocol needs to
     change -- they already operate on SourceFile.language generically.
"""

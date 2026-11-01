"""
base_agent.py

Every agent inherits from BaseAgent. This enforces:
  - a single public entrypoint (`run`)
  - structured logging keyed by attempt_id, so a full repair cycle's
    agent-by-agent trace can be reconstructed later for audit (NFR3)
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-5s | %(name)-18s | %(message)s",
)


class BaseAgent(ABC):
    """Abstract base for all PatchForge-AI agents."""

    name: str = "base-agent"

    def __init__(self):
        self.log = logging.getLogger(self.name)

    def _log(self, attempt_id: str, msg: str, level: int = logging.INFO):
        self.log.log(level, f"[{attempt_id}] {msg}")

    @abstractmethod
    def run(self, *args, **kwargs) -> Any:
        """Each agent implements its single-responsibility action here."""
        raise NotImplementedError

    def timed_run(self, attempt_id: str, *args, **kwargs):
        """Wraps run() with timing + entry/exit logging, used by the orchestrator."""
        start = time.time()
        self._log(attempt_id, f"{self.name} starting")
        try:
            result = self.run(*args, **kwargs)
            elapsed = time.time() - start
            self._log(attempt_id, f"{self.name} finished in {elapsed:.2f}s")
            return result
        except Exception as e:
            self._log(attempt_id, f"{self.name} raised: {e}", level=logging.ERROR)
            raise

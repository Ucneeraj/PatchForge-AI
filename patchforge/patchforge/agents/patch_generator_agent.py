"""
patch_generator_agent.py

Generates a CandidatePatch for a RepairPlan. Two tiers, both behind the
same PatchLLMClient interface:

  1. RuleBasedPatchClient (default, no API key needed): for the two
     vulnerability classes the Scanner currently supports, this derives
     a REAL fix by pattern-matching the actual flagged code (not a
     canned example) and producing replacement source text that can be
     written straight into the real file. This is what makes "point it
     at a random repo" actually work without an LLM.

  2. Any real LLM client (e.g. Anthropic) -- plug in by implementing
     PatchLLMClient and passing it to PatchGeneratorAgent(llm_client=...).
     Needed for strategies RuleBasedPatchClient can't handle.

When RuleBasedPatchClient can't confidently derive a fix (pattern
doesn't match what it expects, or the strategy is unsupported), it
returns replacement_code=None rather than guessing -- the Sandbox-Runner
and Verifier are built to treat that as a real failure, not a silent
false success.
"""

from __future__ import annotations

import re
from typing import Optional, Protocol

from ..protocol import CandidatePatch, RepairPlan
from .base_agent import BaseAgent


class PatchLLMClient(Protocol):
    """Implement this against a real LLM provider for strategies the
    rule-based client can't handle."""

    def generate_patch(
        self,
        strategy: str,
        finding_snippet: str,
        file_path: str,
        prior_reflection: Optional[str],
    ) -> tuple[str, str, Optional[str], Optional[str]]:
        """Returns (diff, rationale, new_test_code, replacement_code)."""
        ...


class RuleBasedPatchClient:
    """
    Default patch client. No external calls, no API key. Derives real
    fixes for two patterns by inspecting the actual flagged snippet:

      - parameterized_query: cursor.execute(f"...{x}...") or
        cursor.execute("..." % x)  ->  cursor.execute("...%s...", (x,))
      - externalize_secret: NAME = "literal" (where NAME looks like a
        credential)  ->  NAME = os.environ["NAME"]

    Anything else returns replacement_code=None -- honest about not
    being able to auto-fix it yet, rather than pretending.
    """

    def generate_patch(
        self,
        strategy: str,
        finding_snippet: str,
        file_path: str,
        prior_reflection: Optional[str],
    ) -> tuple[str, str, Optional[str], Optional[str]]:
        if strategy == "parameterized_query":
            fixed = self._fix_sql_injection(finding_snippet)
            if fixed:
                diff = self._make_diff(file_path, finding_snippet, fixed)
                rationale = (
                    "Automatically rewrote the query to bind the interpolated "
                    "value(s) as parameters instead of formatting them into "
                    "the SQL string."
                )
                test = (
                    "def test_no_sql_injection():\n"
                    "    malicious = \"' OR '1'='1\"\n"
                    "    result = run_query(malicious)\n"
                    "    assert result == []\n"
                )
                return diff, rationale, test, fixed

        if strategy == "externalize_secret":
            fixed = self._fix_hardcoded_secret(finding_snippet)
            if fixed:
                diff = self._make_diff(file_path, finding_snippet, fixed)
                rationale = "Moved the hardcoded credential to an environment variable."
                return diff, rationale, None, fixed

        # Unsupported strategy, or the pattern didn't match what we
        # expected closely enough to safely auto-apply. Be explicit
        # about that rather than fabricating a patch.
        diff = f"--- a/{file_path}\n+++ b/{file_path}\n@@\n# No automatic fix derived for strategy '{strategy}'.\n"
        rationale = (
            f"Could not confidently derive an automatic fix for strategy "
            f"'{strategy}' from the flagged code. This needs either a real "
            f"LLM-backed PatchLLMClient or a wider rule set."
        )
        return diff, rationale, None, None

    # -- CWE-89: SQL injection via string interpolation --------------

    _FSTRING_EXECUTE = re.compile(
        r'(?P<call>[\w.]+\.execute\w*)\(\s*f(?P<quote>["\'])(?P<body>.*)(?P=quote)\s*\)',
        re.DOTALL,
    )
    _PERCENT_EXECUTE = re.compile(
        r'(?P<call>[\w.]+\.execute\w*)\(\s*(?P<quote>["\'])(?P<body>.*)(?P=quote)\s*%\s*(?P<args>.+?)\s*\)',
        re.DOTALL,
    )

    def _fix_sql_injection(self, snippet: str) -> Optional[str]:
        m = self._FSTRING_EXECUTE.search(snippet)
        if m:
            call, body = m.group("call"), m.group("body")
            placeholders = re.findall(r"\{([^}]+)\}", body)
            if not placeholders:
                return None
            new_body = re.sub(r"'\{[^}]+\}'", "%s", body)
            new_body = re.sub(r"\{[^}]+\}", "%s", new_body)
            params = ", ".join(p.strip() for p in placeholders)
            params_tuple = f"({params},)" if len(placeholders) == 1 else f"({params})"
            return f'{call}("{new_body}", {params_tuple})'

        m = self._PERCENT_EXECUTE.search(snippet)
        if m:
            call, body, args = m.group("call"), m.group("body"), m.group("args")
            args = args.strip()
            params_tuple = args if args.startswith("(") else f"({args},)"
            return f'{call}("{body}", {params_tuple})'

        return None

    # -- CWE-798: hardcoded secret ------------------------------------

    _HARDCODED_ASSIGN = re.compile(
        r'^(?P<indent>\s*)(?P<name>\w+)\s*=\s*(?P<quote>["\'])(?P<value>[^"\']+)(?P=quote)\s*$',
        re.MULTILINE,
    )
    _SUSPICIOUS_NAMES = ("password", "secret", "api_key", "apikey", "token")

    def _fix_hardcoded_secret(self, snippet: str) -> Optional[str]:
        m = self._HARDCODED_ASSIGN.search(snippet)
        if not m or m.group("name").lower() not in self._SUSPICIOUS_NAMES:
            return None
        indent, name = m.group("indent"), m.group("name")
        env_var = name.upper()
        return f'{indent}{name} = os.environ["{env_var}"]'

    @staticmethod
    def _make_diff(file_path: str, old: str, new: str) -> str:
        return (
            f"--- a/{file_path}\n+++ b/{file_path}\n@@\n"
            + "\n".join(f"- {line}" for line in old.strip().splitlines())
            + "\n"
            + "\n".join(f"+ {line}" for line in new.strip().splitlines())
        )


class PatchGeneratorAgent(BaseAgent):
    name = "patch-generator"

    def __init__(self, llm_client: Optional[PatchLLMClient] = None):
        super().__init__()
        self.llm_client = llm_client or RuleBasedPatchClient()

    def run(
        self,
        plan: RepairPlan,
        iteration: int,
        prior_reflection: Optional[str] = None,
    ) -> CandidatePatch:
        diff, rationale, test_code, replacement_code = self.llm_client.generate_patch(
            strategy=plan.strategy,
            finding_snippet=plan.finding.snippet,
            file_path=plan.finding.file_path,
            prior_reflection=prior_reflection,
        )
        return CandidatePatch(
            attempt_id=plan.attempt_id,
            iteration=iteration,
            finding_id=plan.finding.finding_id,
            diff=diff,
            rationale=rationale,
            new_test_code=test_code,
            file_path=plan.finding.file_path,
            line_start=plan.finding.line_start,
            line_end=plan.finding.line_end,
            replacement_code=replacement_code,
        )

"""
verifier_agent.py

Implements the Reflexion-style piece of the loop: given a failing
TestResult, produce a structured, human-readable diagnosis of *why* it
failed, and decide whether to retry, escalate, or (on a passing result)
accept. The reflection text is what gets carried forward into the next
Patch-Generator call -- this is the persistent cross-iteration memory
identified as a gap in the literature review.
"""

from __future__ import annotations

from protocol import Decision, ReflectionResult, Status, TestResult
from agents.base_agent import BaseAgent

class VerifierAgent(BaseAgent):
    name = "verifier-reflector"

    def __init__(self, max_iterations: int = 3):
        super().__init__()
        self.max_iterations = max_iterations

    def run(self, result: TestResult) -> ReflectionResult:
        if result.status == Status.PASS:
            return ReflectionResult(
                attempt_id=result.attempt_id,
                iteration=result.iteration,
                decision=Decision.ACCEPT,
                reflection="All tests passed, including the new regression test.",
                carry_forward_context=False,
            )

        if result.iteration >= self.max_iterations:
            return ReflectionResult(
                attempt_id=result.attempt_id,
                iteration=result.iteration,
                decision=Decision.ESCALATE,
                reflection=(
                    f"Exhausted {self.max_iterations} attempts. Last failure: "
                    f"{result.stack_trace_summary or 'no summary available'}."
                ),
                carry_forward_context=False,
            )

        diagnosis = self._diagnose(result)
        return ReflectionResult(
            attempt_id=result.attempt_id,
            iteration=result.iteration,
            decision=Decision.RETRY,
            reflection=diagnosis,
            carry_forward_context=True,
        )

    @staticmethod
    def _diagnose(result: TestResult) -> str:
        """
        Turns raw failure data into an actionable note for the next
        Patch-Generator call. A real implementation could route this
        through an LLM call for richer diagnosis; here it's a direct,
        auditable summarization of the structured failure.
        """
        failed = ", ".join(result.failed_tests) or "unknown test(s)"
        return (
            f"Attempt {result.iteration} failed on: {failed}. "
            f"Detail: {result.stack_trace_summary}. "
            "Next attempt should address this specific failure mode rather "
            "than repeating the same patch strategy verbatim."
        )

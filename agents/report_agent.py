"""
report_agent.py

Turns a RepoScanReport (the aggregated result of scanning/repairing an
entire repo) into a markdown summary a human can actually read --
distinct from RepoScanReport.to_json(), which is for machines/CI.
"""

from __future__ import annotations

from agents.base_agent import BaseAgent


class ReportAgent(BaseAgent):
    name = "report"

    def run(self, report) -> str:
        lines = [
            f"# PatchForge-AI Repair Report",
            "",
            f"**Source:** {report.source}",
            f"**Files scanned:** {report.files_scanned}",
            f"**Findings:** {report.total_findings}  "
            f"({report.total_repaired} repaired, {report.total_escalated} escalated)",
            "",
        ]
        if report.corrected_clone_path:
            lines.insert(3, f"**Corrected copy written to:** {report.corrected_clone_path}")

        if report.skipped_languages:
            skipped = ", ".join(f"{ext} ({n})" for ext, n in report.skipped_languages.items())
            lines.append(f"> Note: files with these extensions were found but not scanned "
                         f"(language not yet supported): {skipped}")
            lines.append("")

        if report.scan_errors:
            lines.append(f"> Note: {len(report.scan_errors)} file(s) could not be parsed "
                         f"and were skipped (not silently ignored):")
            for path, err in report.scan_errors.items():
                lines.append(f">   - `{path}`: {err}")
            lines.append("")

        if not report.outcomes:
            lines.append("No vulnerabilities found in the scanned files.")
            return "\n".join(lines)

        for outcome in report.outcomes:
            status = "✅ Repaired" if outcome.success else "⚠️ Escalated (needs human review)"
            lines.append(f"## {outcome.finding.file_path}:{outcome.finding.line_start} "
                        f"— {outcome.finding.cwe_id} ({outcome.finding.rule_id})")
            lines.append(f"**Status:** {status} in {outcome.iterations_used} iteration(s)")
            lines.append("")
            for r in outcome.reflections:
                lines.append(f"- iter {r.iteration} [{r.decision.value}]: {r.reflection}")
            if outcome.success and outcome.final_diff:
                lines.append("")
                lines.append("```diff")
                lines.append(outcome.final_diff.strip())
                lines.append("```")
            lines.append("")

        return "\n".join(lines)

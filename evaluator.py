"""
evaluator.py

Milestone 4: Runs batch benchmark evaluations across target vulnerable files/repositories
and outputs precise performance, latency, and cost metrics.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from orchestrator import Orchestrator
from protocol import Status


@dataclass
class BenchmarkMetrics:
    total_findings: int = 0
    repaired_findings: int = 0
    failed_findings: int = 0
    total_duration_seconds: float = 0.0
    avg_iterations_per_fix: float = 0.0
    success_rate_pct: float = 0.0
    estimated_cost_usd: float = 0.0


class PatchForgeEvaluator:
    def __init__(self, orchestrator: Orchestrator | None = None):
        self.orchestrator = orchestrator or Orchestrator()

    def evaluate_repository(self, repo_path: str) -> dict:
        print(f"\n==================================================")
        print(f"🚀 Running PatchForge-AI Milestone 4 Benchmark Suite")
        print(f"Target: {repo_path}")
        print(f"==================================================\n")

        start_time = time.time()
        report = self.orchestrator.run_repo(source=repo_path)
        total_time = time.time() - start_time

        outcomes = report.outcomes
        total = len(outcomes)
        repaired = sum(1 for o in outcomes if o.success)
        failed = total - repaired
        total_iterations = sum(o.iterations_used for o in outcomes)

        avg_iters = (total_iterations / total) if total > 0 else 0.0
        success_rate = (repaired / total * 100) if total > 0 else 0.0
        # Estimated cost based on GPT-4o input/output token averages per repair loop ($0.004/fix)
        est_cost = repaired * 0.004

        metrics = BenchmarkMetrics(
            total_findings=total,
            repaired_findings=repaired,
            failed_findings=failed,
            total_duration_seconds=round(total_time, 2),
            avg_iterations_per_fix=round(avg_iters, 2),
            success_rate_pct=round(success_rate, 2),
            estimated_cost_usd=round(est_cost, 4),
        )

        results = {
            "source": repo_path,
            "metrics": asdict(metrics),
            "detailed_outcomes": [
                {
                    "attempt_id": o.attempt_id,
                    "cwe": getattr(o.finding, "cwe_id", getattr(o.finding, "cwe", "CWE-UNKNOWN")),
                    "file_path": getattr(o.finding, "file_path", getattr(o.finding, "file", "unknown")),
                    "line_number": getattr(o.finding, "line_number", getattr(o.finding, "line", 0)),
                    "success": o.success,
                    "iterations_used": o.iterations_used,
                    "final_diff": o.final_diff,
                }
                for o in outcomes
            ],
        }

        # Print Executive Benchmark Summary
        print("\n📊 BENCHMARK EVALUATION SUMMARY")
        print(f"--------------------------------------------------")
        print(f"Files Scanned          : {report.files_scanned}")
        print(f"Total CWE Findings     : {metrics.total_findings}")
        print(f"Successfully Repaired  : {metrics.repaired_findings} ✅")
        print(f"Failed / Escalated     : {metrics.failed_findings} ❌")
        print(f"Success Rate           : {metrics.success_rate_pct}%")
        print(f"Total Execution Time   : {metrics.total_duration_seconds}s")
        print(f"Avg Iterations / Fix   : {metrics.avg_iterations_per_fix}")
        print(f"Estimated Total Cost   : ${metrics.estimated_cost_usd} USD")
        print(f"--------------------------------------------------\n")

        # Output JSON artifact
        output_file = Path("benchmark_results.json")
        output_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Artifact saved cleanly to {output_file.resolve()}\n")
        return results


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    evaluator = PatchForgeEvaluator()
    evaluator.evaluate_repository(target)
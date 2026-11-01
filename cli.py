"""
cli.py

Milestone 5: Production Command-Line Interface (CLI) for automated CI/CD pipeline deployment.
"""

from __future__ import annotations

import argparse
import json
import sys
from orchestrator import Orchestrator


def main():
    parser = argparse.ArgumentParser(
        description="PatchForge-AI: Autonomous Vulnerability Scanner & Remediation CLI"
    )
    parser.add_argument(
        "--repo",
        type=str,
        required=True,
        help="Path or Git URL of the repository to remediate",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum patch-retry iterations per finding (default: 3)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="patchforge_report.json",
        help="Path to output final repair audit report JSON",
    )

    args = parser.parse_args()

    print("🛡️  Initializing PatchForge-AI Remediation Pipeline...")
    orchestrator = Orchestrator(max_iterations=args.max_iterations)

    try:
        report = orchestrator.run_repo(source=args.repo)
        
        summary_data = {
            "source": report.source,
            "files_scanned": report.files_scanned,
            "corrected_clone_path": report.corrected_clone_path,
            "total_outcomes": len(report.outcomes),
            "repaired_count": sum(1 for o in report.outcomes if o.success),
            "outcomes": [
                {
                    "attempt_id": o.attempt_id,
                    "cwe": getattr(o.finding, "cwe_id", getattr(o.finding, "cwe", "CWE-UNKNOWN")),
                    "file": o.finding.file_path,
                    "line": getattr(o.finding, "line_number", getattr(o.finding, "line", 0)),
                    "success": o.success,
                    "iterations": o.iterations_used,
                    "diff": o.final_diff,
                }
                for o in report.outcomes
            ],
        }

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2)

        print(f"\n✅ Remediation complete!")
        print(f"📁 Corrected workspace: {report.corrected_clone_path}")
        print(f"📄 Full JSON Audit Report: {args.output}\n")
        
        # Exit code 0 if all findings repaired, 1 if any escalated
        unrepaired = [o for o in report.outcomes if not o.success]
        sys.exit(1 if unrepaired else 0)

    except Exception as e:
        print(f"\n❌ Pipeline failed with error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
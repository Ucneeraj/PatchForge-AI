"""
main.py

Three modes:

  1. No arguments -- interactive interface: prompts you for a GitHub
     link or local path (or Enter for the built-in single-file demo).

       python -m patchforge.main

  2. A GitHub URL or local path as an argument -- same repo-scan flow,
     no prompt.

       python -m patchforge.main https://github.com/user/repo
       python -m patchforge.main /path/to/local/repo

  3. --demo -- forces the single-file demo without prompting.

       python -m patchforge.main --demo
"""

import sys

from patchforge.orchestrator import Orchestrator
from patchforge.agents.report_agent import ReportAgent

VULNERABLE_SAMPLE = '''
import os

password = "hunter2"

def run_query(user):
    cursor = get_cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user}'")
    return cursor.fetchall()
'''


def run_single_file_demo():
    orchestrator = Orchestrator(max_iterations=3)
    outcomes = orchestrator.run_file("db/queries.py", VULNERABLE_SAMPLE)

    print("\n" + "=" * 70)
    print(f"PatchForge-AI run complete: {len(outcomes)} finding(s) processed")
    print("=" * 70)

    for outcome in outcomes:
        print(f"\nFinding {outcome.finding.finding_id} ({outcome.finding.cwe_id}, "
              f"{outcome.finding.rule_id}) at line {outcome.finding.line_start}")
        print(f"  Success: {outcome.success} in {outcome.iterations_used} iteration(s)")
        for r in outcome.reflections:
            print(f"  - iter {r.iteration} [{r.decision.value}]: {r.reflection}")
        if outcome.success:
            print(f"  Final diff:\n{outcome.final_diff}")


def run_repo_mode(source: str):
    print(f"\nCloning / opening: {source}")
    print("Scanning, patching, and validating against a corrected copy "
          "(original repo is never modified)...\n")
    orchestrator = Orchestrator(max_iterations=3)
    report = orchestrator.run_repo(source)
    print(ReportAgent().run(report))


def interactive():
    print("=" * 70)
    print("PatchForge-AI")
    print("=" * 70)
    source = input(
        "\nEnter a GitHub repo link or local path to scan\n"
        "(or press Enter to run the built-in single-file demo instead): "
    ).strip()
    if source:
        run_repo_mode(source)
    else:
        run_single_file_demo()


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "--demo":
            run_single_file_demo()
        else:
            run_repo_mode(sys.argv[1])
    else:
        interactive()


if __name__ == "__main__":
    main()

"""
scanner_agent.py

The Scanner agent parses a Python source file into an AST and looks for
patterns matching known CWE categories. This is a small, real, working
implementation of two rules (not a stub) so you can see the localization
approach end-to-end; extend `RULES` to add more CWE coverage.

Rule format: each rule is a function(ast.AST, source_lines) -> list[dict]
returning raw match info, which the agent turns into Finding objects.
"""

from __future__ import annotations

import ast
from typing import Callable

from protocol import Finding, new_id
from agents.base_agent import BaseAgent


def _rule_sql_string_formatting(tree: ast.AST, lines: list[str]) -> list[dict]:
    """
    CWE-89 (SQL Injection): flags cursor.execute(...) calls whose SQL
    argument is built with %-formatting, .format(), or an f-string,
    rather than passed as a separate parameter tuple.
    """
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_execute = isinstance(func, ast.Attribute) and func.attr in (
            "execute",
            "executemany",
        )
        if not is_execute or not node.args:
            continue
        first_arg = node.args[0]
        risky = isinstance(first_arg, (ast.JoinedStr,)) or (
            isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod)
        ) or (
            isinstance(first_arg, ast.Call)
            and isinstance(first_arg.func, ast.Attribute)
            and first_arg.func.attr == "format"
        )
        if risky:
            hits.append({
                "line_start": node.lineno,
                "line_end": getattr(node, "end_lineno", node.lineno),
                "cwe_id": "CWE-89",
                "rule_id": "sql-string-formatting",
                "severity": "high",
            })
    return hits


def _rule_hardcoded_secret(tree: ast.AST, lines: list[str]) -> list[dict]:
    """
    CWE-798 (Hardcoded Credentials): flags assignments to names like
    password/secret/api_key/token where the value is a plain string literal.
    """
    hits = []
    suspicious_names = ("password", "secret", "api_key", "apikey", "token")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in suspicious_names:
                hits.append({
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", node.lineno),
                    "cwe_id": "CWE-798",
                    "rule_id": "hardcoded-secret",
                    "severity": "medium",
                })
    return hits


RULES: list[Callable[[ast.AST, list[str]], list[dict]]] = [
    _rule_sql_string_formatting,
    _rule_hardcoded_secret,
]


class ScannerAgent(BaseAgent):
    name = "scanner"

    def run(self, file_path: str, source: str) -> list[Finding]:
        tree = ast.parse(source, filename=file_path)
        lines = source.splitlines()
        findings: list[Finding] = []

        for rule in RULES:
            for hit in rule(tree, lines):
                start, end = hit["line_start"], hit["line_end"]
                snippet = "\n".join(lines[max(0, start - 1):end])
                findings.append(
                    Finding(
                        finding_id=new_id("finding"),
                        file_path=file_path,
                        line_start=start,
                        line_end=end,
                        cwe_id=hit["cwe_id"],
                        rule_id=hit["rule_id"],
                        snippet=snippet,
                        severity=hit["severity"],
                    )
                )
        return findings

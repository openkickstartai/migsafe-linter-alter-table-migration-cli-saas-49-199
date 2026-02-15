#!/usr/bin/env python3
"""MigSafe CLI — Database migration linter & lock time estimator."""
import json
import sys
from pathlib import Path
from typing import List

import typer
from rich.console import Console
from rich.table import Table

from rules import analyze, risk_score, Finding

app = typer.Typer(
    name="migsafe",
    help="\U0001f6e1\ufe0f  MigSafe — Catch dangerous migrations before they lock production",
)
console = Console(stderr=True)
out = Console()

SEV_COLORS = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan"}
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _render_table(findings: List[Finding], filepath: str) -> None:
    if not findings:
        out.print(f"\u2705 [green]{filepath}[/] — no issues")
        return
    tbl = Table(title=f"\U0001f6a8 {filepath}", show_lines=True)
    tbl.add_column("Rule", width=8)
    tbl.add_column("Sev", width=10)
    tbl.add_column("Lock Type", width=22)
    tbl.add_column("Est.", width=10)
    tbl.add_column("Message", min_width=30)
    for f in findings:
        ms = f"{f.lock_ms}ms" if f.lock_ms is not None else "\u26a0\ufe0f unknown"
        tbl.add_row(f.rule_id, f"[{SEV_COLORS[f.severity]}]{f.severity}[/]",
                    f.lock_type, ms, f.message)
    out.print(tbl)
    out.print(f"  Risk score: [bold]{risk_score(findings)}[/]/100\n")


def _to_sarif(all_findings: dict) -> dict:
    results = []
    for fp, fs in all_findings.items():
        for f in fs:
            lvl = "error" if f.severity in ("critical", "high") else "warning"
            results.append({"ruleId": f.rule_id, "level": lvl,
                "message": {"text": f.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": fp},
                    "region": {"startLine": f.line}}}]})
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {
        "name": "MigSafe", "version": "1.0.0"}}, "results": results}]}


def _collect_sql_files(paths: List[str]) -> List[Path]:
    files: List[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files.extend(sorted(path.glob("**/*.sql")))
        elif path.is_file():
            files.append(path)
        else:
            console.print(f"[red]Error: {p} not found[/]")
            raise typer.Exit(1)
    return files


@app.command()
def lint(
    paths: List[str] = typer.Argument(..., help="SQL migration files or directories"),
    rows: int = typer.Option(0, "--rows", "-r", help="Estimated row count for lock time"),
    fmt: str = typer.Option("text", "--format", "-f", help="Output: text, json, sarif"),
    fail_on: str = typer.Option("high", "--fail-on", help="Min severity to exit 1"),
) -> None:
    """Lint SQL migration files for dangerous operations."""
    sql_files = _collect_sql_files(paths)
    if not sql_files:
        console.print("[yellow]No .sql files found[/]")
        raise typer.Exit(0)
    all_findings = {}
    for sf in sql_files:
        all_findings[str(sf)] = analyze(sf.read_text(), rows)
    if fmt == "json":
        data = {fp: [{"rule_id": f.rule_id, "severity": f.severity,
            "message": f.message, "line": f.line, "lock_type": f.lock_type,
            "lock_ms": f.lock_ms} for f in fs] for fp, fs in all_findings.items()}
        print(json.dumps(data, indent=2))
    elif fmt == "sarif":
        print(json.dumps(_to_sarif(all_findings), indent=2))
    else:
        for fp, fs in all_findings.items():
            _render_table(fs, fp)
    threshold = SEV_RANK.get(fail_on, 3)
    failed = any(SEV_RANK.get(f.severity, 0) >= threshold
                 for fs in all_findings.values() for f in fs)
    raise typer.Exit(1 if failed else 0)


if __name__ == "__main__":
    app()

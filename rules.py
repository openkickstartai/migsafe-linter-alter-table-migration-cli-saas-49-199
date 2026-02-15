"""MigSafe rule engine — detect dangerous SQL migration patterns."""
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    line: int
    sql: str
    lock_type: str
    lock_ms: Optional[int] = None


RULES: List[Tuple[str, str, str, str, str, Optional[int]]] = [
    ("BAN001", r"\bDROP\s+TABLE\b", "critical",
     "DROP TABLE permanently deletes data and all indexes",
     "ACCESS EXCLUSIVE", 10),
    ("BAN002", r"\bALTER\s+TABLE\s+\S+\s+DROP\s+COLUMN\b", "high",
     "DROP COLUMN is irreversible and may break running queries",
     "ACCESS EXCLUSIVE", 50),
    ("BAN003", r"\bALTER\s+TABLE\s+\S+\s+RENAME\b", "medium",
     "Renaming table/column will break application queries",
     "ACCESS EXCLUSIVE", 5),
    ("LCK001",
     r"\bADD\s+(?:COLUMN\s+)?\S+\s+\S+[^;]*\bNOT\s+NULL\b(?![^;]*\bDEFAULT\b)",
     "critical",
     "Adding NOT NULL column without DEFAULT rewrites entire table under lock",
     "ACCESS EXCLUSIVE", None),
    ("LCK002", r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY\b)", "high",
     "CREATE INDEX without CONCURRENTLY blocks all writes",
     "SHARE", None),
    ("LCK003",
     r"\bADD\s+(?:CONSTRAINT\s+\S+\s+)?FOREIGN\s+KEY\b(?![^;]*\bNOT\s+VALID\b)",
     "high",
     "Adding FK without NOT VALID scans entire table under lock",
     "SHARE ROW EXCLUSIVE", None),
    ("LCK004",
     r"\bALTER\s+TABLE\s+\S+\s+ALTER\s+COLUMN\s+\S+\s+(?:SET\s+DATA\s+)?TYPE\b",
     "critical",
     "Changing column type rewrites the entire table under ACCESS EXCLUSIVE lock",
     "ACCESS EXCLUSIVE", None),
    ("LCK005",
     r"\bALTER\s+TABLE\s+\S+\s+ALTER\s+COLUMN\s+\S+\s+SET\s+NOT\s+NULL\b",
     "high",
     "SET NOT NULL scans full table; use CHECK constraint + NOT VALID instead",
     "ACCESS EXCLUSIVE", None),
]


def estimate_lock_ms(base_ms: Optional[int], rows: int) -> Optional[int]:
    """Estimate lock duration in ms. Returns None if unknowable."""
    if rows <= 0:
        return base_ms
    return max(base_ms or 1, rows // 10000 + (base_ms or 0))


def _split_statements(sql: str):
    """Yield (statement_text, line_number) pairs."""
    parts = sql.split(";")
    offset = 0
    for part in parts:
        text = part.strip()
        if text and not text.lstrip().startswith("--"):
            line = sql[:offset].count("\n") + 1
            yield " ".join(text.split()), line
        offset += len(part) + 1


def analyze(sql: str, rows: int = 0) -> List[Finding]:
    """Analyze SQL string for dangerous migration patterns."""
    findings: List[Finding] = []
    for stmt, line in _split_statements(sql):
        for rid, pattern, sev, msg, lock, base in RULES:
            if re.search(pattern, stmt, re.IGNORECASE):
                findings.append(Finding(
                    rule_id=rid, severity=sev, message=msg, line=line,
                    sql=stmt[:120], lock_type=lock,
                    lock_ms=estimate_lock_ms(base, rows),
                ))
    return findings


def risk_score(findings: List[Finding]) -> int:
    """Calculate 0-100 risk score from findings."""
    return min(100, sum(SEVERITY_WEIGHT.get(f.severity, 1) * 25 for f in findings))

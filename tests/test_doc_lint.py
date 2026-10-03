import re
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_PATTERNS = [
    (r"\b0%\s*FPR\b", "0% FPR claim (must state 0/N with 95% Clopper-Pearson upper bound)"),
    (r"\b0\.00%\s*FPR\b", "0.00% FPR claim (must state 0/N with 95% Clopper-Pearson upper bound)"),
    (r"\b0\s+false\s+alarms\s+on\s+VoIP\b", "0 false alarms on VoIP claim (baseline lacks VoIP traffic)"),
    (r"\bFPR\s*<\s*1%\b", "FPR < 1% overstatement (finite baseline sample bound is ~8.04%-8.41%)"),
]

DOC_EXTENSIONS = {".md", ".rst", ".txt"}
EXCLUDE_DIRS = {".git", ".pytest_cache", "node_modules", "dist", ".venv", "tmp", "logs", "tasks"}
EXCLUDE_FILES = {"03.md", "04.md", "test_doc_lint.py"}  # Prompt files that quote prohibited phrases for audit rules


def test_no_prohibited_fpr_claims_in_docs():
    """
    Item 3.1: Verify no dishonest anomaly claims ('0% FPR', 'FPR < 1%', '0 false alarms on VoIP')
    exist across documentation, code comments, and reports.
    """
    violations = []

    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if path.name in EXCLUDE_FILES:
            continue
        if path.suffix not in DOC_EXTENSIONS and path.suffix not in {".py", ".jsx", ".js", ".json"}:
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            # Skip historical disclosures or explicitly debunked citations in verification reports
            if "Integrity Clarification" in line or "debunked" in line.lower() or "prohibited" in line.lower():
                continue
            for pattern, reason in FORBIDDEN_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    violations.append(f"{path.relative_to(PROJECT_ROOT)}:{line_num} -> {reason} | Line: {line.strip()[:80]}")

    assert not violations, f"Found prohibited statistical claims:\n" + "\n".join(violations)

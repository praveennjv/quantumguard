from __future__ import annotations

import json
from pathlib import Path

from scanner.models import Finding


def fingerprint(finding: Finding) -> str:
    return f"{finding.rule_id}|{finding.algorithm}|{Path(finding.location.file).name}|{finding.location.line}"


def load_baseline(path: str) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = data.get("findings") or data
    keys = set()
    for item in findings:
        loc = item.get("location") or {}
        keys.add(
            f"{item.get('rule_id')}|{item.get('algorithm')}|{Path(str(loc.get('file', ''))).name}|{loc.get('line')}"
        )
    return keys


def new_findings(findings: list[Finding], baseline: set[str]) -> list[Finding]:
    return [f for f in findings if fingerprint(f) not in baseline]

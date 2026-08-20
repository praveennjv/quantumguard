"""SARIF 2.1.0 writer for GitHub code scanning."""

from __future__ import annotations

from typing import Any

from scanner.models import ScanResult, Severity

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}


def to_sarif(result: ScanResult) -> dict[str, Any]:
    rules = {}
    results = []
    for finding in result.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.algorithm,
            "shortDescription": {"text": f"{finding.algorithm} cryptographic usage"},
            "fullDescription": {"text": finding.why_problem},
            "help": {
                "text": finding.recommended_action,
                "markdown": (
                    f"**Why this is a problem**\n\n{finding.why_problem}\n\n"
                    f"**Why it is quantum-relevant**\n\n{finding.why_quantum}\n\n"
                    f"**Recommended action**\n\n{finding.recommended_action}\n\n"
                    "_QuantumGuard does not detect active quantum attacks._"
                ),
            },
            "properties": {
                "security-severity": str(min(10.0, finding.score / 10)),
                "precision": "high" if finding.confidence >= 0.85 else "medium",
                "tags": ["security", "cryptography", "quantum", finding.quantum_status.value],
            },
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": LEVEL[finding.severity],
                "message": {
                    "text": (
                        f"{finding.algorithm} ({finding.severity.value}, score {finding.score}, "
                        f"{finding.quantum_status.value}) in {finding.location.file}:{finding.location.line}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.location.file.replace("\\", "/")},
                            "region": {
                                "startLine": finding.location.line,
                                "startColumn": finding.location.column,
                                "snippet": {"text": finding.evidence},
                            },
                        }
                    }
                ],
                "properties": {
                    "score": finding.score,
                    "risk_model": finding.risk_model,
                    "confidence": finding.confidence,
                    "hndl": finding.hndl_risk,
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "QuantumGuard",
                        "version": result.version,
                        "informationUri": "https://github.com/quantumguard/quantumguard",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

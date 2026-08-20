from __future__ import annotations

import csv
import io

from scanner.models import ScanResult


def to_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "id",
            "severity",
            "score",
            "algorithm",
            "quantum_status",
            "file",
            "line",
            "function",
            "library",
            "usage",
            "confidence",
            "risk_model",
            "hndl",
        ]
    )
    for f in result.findings:
        writer.writerow(
            [
                f.id,
                f.severity.value,
                f.score,
                f.algorithm,
                f.quantum_status.value,
                f.location.file,
                f.location.line,
                f.location.function or "",
                f.library or "",
                f.usage or "",
                f.confidence,
                f.risk_model,
                f.hndl_risk or "",
            ]
        )
    return buf.getvalue()

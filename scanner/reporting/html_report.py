from __future__ import annotations

import html

from scanner.models import ScanResult


def to_html(result: ScanResult) -> str:
    rows = []
    for f in result.findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(f.severity.value)}</td>"
            f"<td>{f.score}</td>"
            f"<td>{html.escape(f.algorithm)}</td>"
            f"<td>{html.escape(f.quantum_status.value)}</td>"
            f"<td>{html.escape(f.location.file)}</td>"
            f"<td>{f.location.line}</td>"
            f"<td><pre>{html.escape(f.evidence)}</pre></td>"
            "</tr>"
        )
    table = "\n".join(rows) or "<tr><td colspan='7'>No findings</td></tr>"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>QuantumGuard report</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; background: #0b1220; color: #e6edf3; }}
    a {{ color: #7dd3fc; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #334155; padding: 0.5rem; vertical-align: top; }}
    pre {{ white-space: pre-wrap; }}
    .banner {{ background: #1e293b; padding: 1rem; border-radius: 8px; }}
  </style>
</head>
<body>
  <h1>QuantumGuard</h1>
  <p class="banner">Cryptographic inventory and <strong>future</strong> quantum-security risk.
  This report does <strong>not</strong> detect active quantum attacks. Risk model: {html.escape(result.risk_model)}.</p>
  <p>Files scanned: {result.stats.get("files")} · Findings: {len(result.findings)} ·
  Quantum-vulnerable (algorithm class): {result.stats.get("quantum_vulnerable")}</p>
  <table>
    <thead><tr><th>Severity</th><th>Score</th><th>Algorithm</th><th>Quantum</th><th>File</th><th>Line</th><th>Evidence</th></tr></thead>
    <tbody>
    {table}
    </tbody>
  </table>
</body>
</html>
"""

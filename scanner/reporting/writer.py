from __future__ import annotations

import json
from pathlib import Path

from scanner.cbom import to_cyclonedx
from scanner.models import ScanResult
from scanner.reporting.csv_report import to_csv
from scanner.reporting.html_report import to_html
from scanner.reporting.sarif import to_sarif

DEFAULT_NAMES = {
    "json": "quantumguard-results.json",
    "sarif": "quantumguard-results.sarif",
    "cbom": "quantumguard-cbom.json",
    "html": "quantumguard-report.html",
    "csv": "quantumguard-results.csv",
}


def render(result: ScanResult, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2)
    if fmt == "sarif":
        return json.dumps(to_sarif(result), indent=2)
    if fmt == "cbom":
        return json.dumps(to_cyclonedx(result), indent=2)
    if fmt == "html":
        return to_html(result)
    if fmt == "csv":
        return to_csv(result)
    raise ValueError(f"unsupported format: {fmt}")


def write_report(result: ScanResult, formats: list[str], output: str | None) -> None:
    out = Path(output) if output else None
    multi = len(formats) > 1
    for fmt in formats:
        text = render(result, fmt)
        if out is None:
            print(text)
            continue
        if multi or out.is_dir() or (not out.suffix):
            dest_dir = out if out.suffix == "" or out.is_dir() else out.parent
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / DEFAULT_NAMES[fmt]
        else:
            dest = out
            dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")

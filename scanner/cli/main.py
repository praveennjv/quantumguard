from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner import __version__
from scanner.analyzers.engine import scan_path
from scanner.detectors.registry import list_rules
from scanner.models import SEVERITY_ORDER, ScanContext, Severity
from scanner.reporting.baseline import load_baseline, new_findings
from scanner.reporting.writer import write_report

EXIT_OK = 0
EXIT_POLICY = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quantumguard",
        description=(
            "Discover cryptographic usage, emit CBOM/SARIF, and score quantum-security risk. "
            "Does not detect active quantum attacks."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a path for cryptographic usage")
    scan.add_argument("path", nargs="?", default=".", help="Directory or file to scan")
    scan.add_argument(
        "--format",
        dest="formats",
        action="append",
        choices=["json", "sarif", "cbom", "html", "csv"],
        help="Output format (repeatable). Default: json",
    )
    scan.add_argument("--output", "-o", help="Output file (single format) or directory")
    scan.add_argument(
        "--fail-on",
        default="high",
        choices=["informational", "low", "medium", "high", "critical", "never"],
        help="Minimum severity that fails CI (default: high)",
    )
    scan.add_argument("--baseline", help="Baseline JSON; only new findings fail the gate")
    scan.add_argument("--context", help="YAML/JSON application context for risk model v2+")
    scan.add_argument(
        "--risk-model",
        default="v1-algorithm-only",
        choices=["v1-algorithm-only", "v2-application-context", "v3-data-lifetime", "v4-business"],
    )
    scan.add_argument("--quiet", action="store_true")

    sub.add_parser("version", help="Print scanner version")
    sub.add_parser("rules", help="List detection rules")
    return parser


def _load_context(path: str | None, risk_model: str, fail_on: str) -> ScanContext:
    data: dict = {}
    if path:
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        if p.suffix.lower() in {".yml", ".yaml"}:
            import yaml

            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
    ctx = ScanContext.from_mapping(data)
    ctx.risk_model = risk_model
    ctx.fail_on = fail_on
    return ctx


def _policy_violated(result, fail_on: str, baseline_path: str | None) -> bool:
    if fail_on == "never":
        return False
    findings = result.findings
    if baseline_path:
        baseline = load_baseline(baseline_path)
        findings = new_findings(findings, baseline)
    threshold = SEVERITY_ORDER[Severity(fail_on)]
    return any(SEVERITY_ORDER[f.severity] >= threshold for f in findings)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "version":
            print(__version__)
            return EXIT_OK
        if args.command == "rules":
            for rule in list_rules():
                print(f"{rule['id']}\t{rule['algorithm']}\t{rule['languages']}")
            return EXIT_OK

        ctx = _load_context(args.context, args.risk_model, args.fail_on)
        result = scan_path(args.path, ctx)
        formats = args.formats or ["json"]
        write_report(result, formats, args.output)

        if not args.quiet:
            print(
                f"QuantumGuard {__version__} scanned {result.stats.get('files', 0)} files; "
                f"{len(result.findings)} findings (model {result.risk_model}).",
                file=sys.stderr,
            )
            print(
                "This scan does not detect active quantum attacks.",
                file=sys.stderr,
            )

        if result.errors and not result.findings:
            return EXIT_ERROR
        if _policy_violated(result, args.fail_on, args.baseline):
            return EXIT_POLICY
        return EXIT_OK
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(f"quantumguard error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

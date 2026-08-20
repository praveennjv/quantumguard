from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scanner import __version__
from scanner.detectors.registry import ALL_RULES
from scanner.ir import IRNode
from scanner.knowledge.catalog import algorithm_info
from scanner.languages import adapter_for
from scanner.models import Finding, Location, ScanContext, ScanResult
from scanner.risk.engine import classify_quantum, score_finding
from scanner.risk.hndl import assess_hndl

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "coverage",
}


def _iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if adapter_for(p.suffix):
            files.append(p)
    return files


def _finding_id(file: str, line: int, rule: str, algo: str) -> str:
    raw = f"{file}:{line}:{rule}:{algo}"
    return "QG-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _confidence(node: IRNode, extra: dict) -> float:
    conf = 0.72
    if any(isinstance(a, str) for a in node.args):
        conf += 0.12
    if extra.get("library"):
        conf += 0.08
    if node.function:
        conf += 0.05
    return min(0.99, conf)


def detect_on_nodes(nodes: list[IRNode], context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for node in nodes:
        matched_algo_rules = []
        for rule in ALL_RULES:
            extra = rule.match(node)
            if not extra:
                continue
            matched_algo_rules.append((rule, extra))
        # Prefer specific algorithms over generic library hits
        specific = [(r, e) for r, e in matched_algo_rules if r.id != "QG-LIB"]
        chosen = specific or matched_algo_rules
        for rule, extra in chosen:
            algorithm = extra.get("algorithm") or rule.algorithm
            variant = extra.get("variant") or rule.variant
            key_size = extra.get("key_size") or rule.default_key_size
            curve = extra.get("curve") or extra.get("variant") or rule.default_curve
            mode = extra.get("mode") or rule.default_mode
            padding = extra.get("padding") or rule.default_padding
            usage = extra.get("usage") or rule.usage_hint
            purpose = extra.get("purpose") or rule.purpose_hint
            library = extra.get("library") or rule.library_hint
            qstatus = classify_quantum(algorithm, variant)
            hndl_level, hndl_why = assess_hndl(algorithm, usage, context)
            score, severity, model = score_finding(
                algorithm=algorithm,
                variant=variant,
                key_size=key_size,
                curve=curve,
                mode=mode,
                usage=usage,
                purpose=purpose,
                context=context,
                hndl_level=hndl_level,
            )
            info = algorithm_info(algorithm)
            findings.append(
                Finding(
                    id=_finding_id(node.file, node.line, rule.id, algorithm),
                    rule_id=rule.id,
                    algorithm=algorithm,
                    variant=variant,
                    key_size=key_size,
                    curve=curve,
                    mode=mode,
                    padding=padding,
                    library=library,
                    usage=usage,
                    purpose=purpose,
                    protocol=extra.get("protocol"),
                    data_flow=extra.get("data_flow"),
                    dependency=extra.get("dependency"),
                    location=Location(
                        file=node.file,
                        line=node.line,
                        column=node.column,
                        function=node.function,
                        class_name=node.class_name,
                    ),
                    language=node.language,
                    snippet=node.snippet,
                    evidence=node.snippet,
                    confidence=_confidence(node, extra),
                    quantum_status=qstatus,
                    severity=severity,
                    score=score,
                    risk_model=model,
                    why_problem=rule.why_problem,
                    why_quantum=rule.why_quantum + (f" Catalog: {info['summary']}" if info else ""),
                    recommended_action=rule.recommended_action,
                    migration_complexity=rule.migration_complexity,
                    hndl_risk=hndl_level,
                    hndl_rationale=hndl_why,
                    application=context.application,
                    environment=context.environment,
                    business_owner=context.business_owner,
                )
            )
    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.location.file, f.location.line, f.rule_id, f.algorithm)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan_path(target: str | Path, context: ScanContext | None = None) -> ScanResult:
    context = context or ScanContext()
    root = Path(target).resolve()
    files = _iter_files(root)
    findings: list[Finding] = []
    errors: list[str] = []
    parsed = 0
    from scanner.analyzers.dependencies import discover_libraries

    libraries = discover_libraries(root)
    for file in files:
        adapter = adapter_for(file.suffix)
        if not adapter:
            continue
        try:
            source = file.read_text(encoding="utf-8", errors="replace")
            nodes = adapter.parse(file, source)
            parsed += 1
            findings.extend(detect_on_nodes(nodes, context))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{file}: {exc}")

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    qv = sum(1 for f in findings if f.quantum_status.value == "quantum-vulnerable")
    stats = {
        "files": parsed,
        "findings": len(findings),
        "by_severity": by_sev,
        "quantum_vulnerable": qv,
        "languages": sorted({f.language for f in findings}),
    }
    return ScanResult(
        version=__version__,
        risk_model=context.risk_model,
        target=str(root),
        findings=findings,
        libraries=libraries,
        stats=stats,
        errors=errors,
    )


def dump_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)

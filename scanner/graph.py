"""Contextual risk graph (repository → algorithm → data)."""

from __future__ import annotations

from typing import Any

from scanner.models import ScanResult


def build_graph(result: ScanResult) -> dict[str, Any]:
    nodes = []
    edges = []
    repo_id = "repo:target"
    nodes.append({"id": repo_id, "type": "repository", "label": result.target})
    if result.findings and result.findings[0].application:
        app_id = f"app:{result.findings[0].application}"
        nodes.append({"id": app_id, "type": "application", "label": result.findings[0].application})
        edges.append({"from": repo_id, "to": app_id, "type": "contains"})
    else:
        app_id = repo_id
    for f in result.findings:
        algo_id = f"algo:{f.algorithm}"
        if not any(n["id"] == algo_id for n in nodes):
            nodes.append({"id": algo_id, "type": "algorithm", "label": f.algorithm})
        file_id = f"file:{f.location.file}"
        if not any(n["id"] == file_id for n in nodes):
            nodes.append({"id": file_id, "type": "component", "label": f.location.file})
            edges.append({"from": app_id, "to": file_id, "type": "contains"})
        edges.append({"from": file_id, "to": algo_id, "type": "uses"})
        if f.usage:
            usage_id = f"usage:{f.usage}"
            if not any(n["id"] == usage_id for n in nodes):
                nodes.append({"id": usage_id, "type": "api", "label": f.usage})
            edges.append({"from": algo_id, "to": usage_id, "type": "purpose"})
    return {"nodes": nodes, "edges": edges, "risk_model": result.risk_model}

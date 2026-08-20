"""Placeholder for richer intra-procedural taint tracking (Milestone 2+)."""

from scanner.ir import IRNode


def summarize_flow(node: IRNode) -> str | None:
    if node.function:
        return f"{node.function} -> {node.callee}"
    return None

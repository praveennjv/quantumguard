from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from scanner.ir import IRNode

MatchFn = Callable[[IRNode], dict[str, Any] | None]


@dataclass(frozen=True)
class Rule:
    id: str
    algorithm: str
    variant: str | None
    quantum_status: str
    purpose_hint: str
    usage_hint: str
    library_hint: str | None
    languages: str
    match: MatchFn
    why_problem: str
    why_quantum: str
    recommended_action: str
    migration_complexity: str
    default_key_size: int | None = None
    default_curve: str | None = None
    default_mode: str | None = None
    default_padding: str | None = None


def _s(value: Any) -> str:
    return str(value).lower() if value is not None else ""


def callee_contains(node: IRNode, *needles: str) -> bool:
    hay = _s(node.callee) + " " + _s(node.resolved_name)
    return any(n.lower() in hay for n in needles)


def arg_contains(node: IRNode, *needles: str) -> bool:
    joined = " ".join(_s(a) for a in node.args)
    joined += " " + " ".join(_s(v) for v in node.keywords.values())
    return any(n.lower() in joined for n in needles)


def first_string_arg(node: IRNode) -> str | None:
    for a in node.args:
        if isinstance(a, str) and a and not a.startswith("<"):
            return a
    for v in node.keywords.values():
        if isinstance(v, str):
            return v
    return None


def int_arg(node: IRNode) -> int | None:
    for a in node.args:
        if isinstance(a, int):
            return a
        if isinstance(a, str) and a.isdigit():
            return int(a)
    for v in node.keywords.values():
        if isinstance(v, int):
            return v
    return None

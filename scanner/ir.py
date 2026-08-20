from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IRNode:
    """Language-independent crypto-relevant event."""

    language: str
    file: str
    line: int
    column: int
    kind: str
    callee: str
    args: list[Any] = field(default_factory=list)
    keywords: dict[str, Any] = field(default_factory=dict)
    function: str | None = None
    class_name: str | None = None
    snippet: str = ""
    resolved_name: str = ""
    imports: dict[str, str] = field(default_factory=dict)
    source_text: str = ""

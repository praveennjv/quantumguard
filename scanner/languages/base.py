from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from scanner.ir import IRNode


class LanguageAdapter(ABC):
    language: str
    extensions: tuple[str, ...]

    @abstractmethod
    def parse(self, path: Path, source: str) -> list[IRNode]:
        raise NotImplementedError


def snippet_at(source: str, line: int, radius: int = 0) -> str:
    lines = source.splitlines()
    idx = max(line - 1, 0)
    if idx >= len(lines):
        return ""
    start = max(0, idx - radius)
    end = min(len(lines), idx + radius + 1)
    return "\n".join(lines[start:end]).strip()

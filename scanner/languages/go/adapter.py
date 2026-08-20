"""Future language adapters (Go, C, C++, C#, Rust) — Milestone 1 ships Java/Python/JS/TS."""

from pathlib import Path

from scanner.ir import IRNode
from scanner.languages.base import LanguageAdapter


class UnsupportedAdapter(LanguageAdapter):
    def parse(self, path: Path, source: str) -> list[IRNode]:
        return []


class GoAdapter(UnsupportedAdapter):
    language = "go"
    extensions = (".go",)


class CAdapter(UnsupportedAdapter):
    language = "c"
    extensions = (".c", ".h")


class CppAdapter(UnsupportedAdapter):
    language = "cpp"
    extensions = (".cpp", ".cc", ".cxx", ".hpp")


class CSharpAdapter(UnsupportedAdapter):
    language = "csharp"
    extensions = (".cs",)


class RustAdapter(UnsupportedAdapter):
    language = "rust"
    extensions = (".rs",)

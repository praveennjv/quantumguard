"""TypeScript adapter: strip types, then reuse the JavaScript esprima pipeline."""

from __future__ import annotations

import re
from pathlib import Path

import esprima

from scanner.ir import IRNode
from scanner.languages.base import LanguageAdapter
from scanner.languages.javascript.adapter import JavaScriptAdapter, _JsCollector

_TYPE_ASSERT = re.compile(r"\s+as\s+[A-Za-z_][\w.<>,\s|&]*")
_INTERFACE = re.compile(r"^\s*(export\s+)?interface\s+\w+[\s\S]*?\{[\s\S]*?\}\s*", re.M)
_TYPE_ALIAS = re.compile(r"^\s*(export\s+)?type\s+\w+[^=]*=.*;\s*$", re.M)
_PARAM_TYPE = re.compile(r"(\(|,)\s*([A-Za-z_][\w]*)(\?)?\s*:\s*[^,)=]+")
_RET_TYPE = re.compile(r"\)\s*:\s*[^{=]+\{")
_ANGLE_GENERIC = re.compile(r"([A-Za-z_][\w]*)\s*<[^>]+>")


def strip_types(source: str) -> str:
    source = re.sub(_INTERFACE, "", source)
    source = re.sub(_TYPE_ALIAS, "", source)
    source = _TYPE_ASSERT.sub("", source)
    for _ in range(8):
        updated = _PARAM_TYPE.sub(r"\1 \2", source)
        if updated == source:
            break
        source = updated
    source = _RET_TYPE.sub(") {", source)
    source = _ANGLE_GENERIC.sub(r"\1", source)
    source = source.replace("public ", "").replace("private ", "").replace("protected ", "")
    source = source.replace("readonly ", "")
    return source


class TypeScriptAdapter(LanguageAdapter):
    language = "typescript"
    extensions = (".ts", ".tsx")

    def parse(self, path: Path, source: str) -> list[IRNode]:
        js = strip_types(source)
        adapter = JavaScriptAdapter()
        try:
            tree = esprima.parseModule(js, {"loc": True, "jsx": True, "tolerant": True})
        except Exception:
            try:
                tree = esprima.parseScript(js, {"loc": True, "tolerant": True})
            except Exception:
                return adapter.parse(path, js)
        collector = _JsCollector(str(path), source, "typescript")
        collector.visit(tree.toDict())
        return collector.nodes

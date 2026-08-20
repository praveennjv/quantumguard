"""JavaScript adapter using esprima AST."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import esprima

from scanner.ir import IRNode
from scanner.languages.base import LanguageAdapter, snippet_at


class JavaScriptAdapter(LanguageAdapter):
    language = "javascript"
    extensions = (".js", ".jsx", ".mjs", ".cjs")

    def parse(self, path: Path, source: str) -> list[IRNode]:
        try:
            tree = esprima.parseModule(source, {"loc": True, "jsx": True, "tolerant": True})
        except Exception:
            try:
                tree = esprima.parseScript(source, {"loc": True, "tolerant": True})
            except Exception:
                return []
        collector = _JsCollector(str(path), source, "javascript")
        collector.visit(tree.toDict() if hasattr(tree, "toDict") else _to_dict(tree))
        return collector.nodes


def _to_dict(node: Any) -> dict:
    if hasattr(node, "toDict"):
        return node.toDict()
    if isinstance(node, dict):
        return node
    data = {}
    for key in dir(node):
        if key.startswith("_"):
            continue
        try:
            data[key] = getattr(node, key)
        except Exception:
            continue
    return data


class _JsCollector:
    def __init__(self, file: str, source: str, language: str) -> None:
        self.file = file
        self.source = source
        self.language = language
        self.nodes: list[IRNode] = []
        self.imports: dict[str, str] = {}
        self.aliases: dict[str, str] = {}
        self.func_stack: list[str] = []

    def visit(self, node: Any) -> None:
        if node is None:
            return
        if isinstance(node, list):
            for item in node:
                self.visit(item)
            return
        if not isinstance(node, dict):
            node = _to_dict(node)
            if not isinstance(node, dict):
                return
        ntype = node.get("type")
        if ntype == "ImportDeclaration":
            src = (node.get("source") or {}).get("value")
            for spec in node.get("specifiers") or []:
                local = ((spec.get("local") or {}).get("name")) or ""
                imported = ((spec.get("imported") or {}).get("name")) or local
                if src:
                    self.imports[local] = f"{src}.{imported}"
                    self.aliases[local] = f"{src}.{imported}"
        elif ntype in {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}:
            ident = node.get("id") or {}
            name = ident.get("name") if isinstance(ident, dict) else None
            if name:
                self.func_stack.append(name)
            self._walk_children(node)
            if name:
                self.func_stack.pop()
            return
        elif ntype == "VariableDeclarator":
            ident = (node.get("id") or {}).get("name")
            init = node.get("init")
            resolved = self._expr_name(init) if init else None
            if ident and resolved:
                self.aliases[ident] = resolved
                if "require" in resolved or (isinstance(init, dict) and init.get("type") == "CallExpression"):
                    callee = self._expr_name(init.get("callee") if isinstance(init, dict) else None)
                    if callee.endswith("require") or callee == "require":
                        args = init.get("arguments") or []
                        if args:
                            mod = (args[0] or {}).get("value") if isinstance(args[0], dict) else None
                            if ident and mod:
                                self.imports[ident] = str(mod)
                                self.aliases[ident] = str(mod)
        elif ntype == "CallExpression":
            callee = self._expr_name(node.get("callee"))
            args = [self._arg(a) for a in node.get("arguments") or []]
            loc = (node.get("loc") or {}).get("start") or {}
            line = loc.get("line") or 1
            self.nodes.append(
                IRNode(
                    language=self.language,
                    file=self.file,
                    line=line,
                    column=loc.get("column", 0) + 1,
                    kind="call",
                    callee=callee,
                    args=args,
                    function=self.func_stack[-1] if self.func_stack else None,
                    snippet=snippet_at(self.source, line),
                    resolved_name=callee,
                    imports=dict(self.imports),
                    source_text=self.source,
                )
            )
        elif ntype == "NewExpression":
            callee = self._expr_name(node.get("callee"))
            args = [self._arg(a) for a in node.get("arguments") or []]
            loc = (node.get("loc") or {}).get("start") or {}
            line = loc.get("line") or 1
            self.nodes.append(
                IRNode(
                    language=self.language,
                    file=self.file,
                    line=line,
                    column=loc.get("column", 0) + 1,
                    kind="construct",
                    callee=callee,
                    args=args,
                    function=self.func_stack[-1] if self.func_stack else None,
                    snippet=snippet_at(self.source, line),
                    resolved_name=callee,
                    imports=dict(self.imports),
                    source_text=self.source,
                )
            )
        self._walk_children(node)

    def _walk_children(self, node: dict) -> None:
        for key, value in node.items():
            if key in {"type", "loc", "range"}:
                continue
            if isinstance(value, (dict, list)):
                self.visit(value)

    def _expr_name(self, node: Any) -> str:
        if not node:
            return ""
        if not isinstance(node, dict):
            node = _to_dict(node)
        ntype = node.get("type")
        if ntype == "Identifier":
            name = node.get("name") or ""
            return self.aliases.get(name, name)
        if ntype == "MemberExpression":
            obj = self._expr_name(node.get("object"))
            prop = node.get("property") or {}
            pname = prop.get("name") or prop.get("value") or ""
            return f"{obj}.{pname}" if obj else str(pname)
        if ntype == "CallExpression":
            return self._expr_name(node.get("callee"))
        return ntype or ""

    def _arg(self, node: Any):
        if not node:
            return None
        if not isinstance(node, dict):
            node = _to_dict(node)
        ntype = node.get("type")
        if ntype == "Literal":
            return node.get("value")
        if ntype == "Identifier":
            name = node.get("name")
            return self.aliases.get(name, name)
        return self._expr_name(node)

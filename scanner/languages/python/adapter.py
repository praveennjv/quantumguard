"""Python language adapter: stdlib AST + intra-procedural name resolution."""

from __future__ import annotations

import ast
from pathlib import Path

from scanner.ir import IRNode
from scanner.languages.base import LanguageAdapter, snippet_at


class PythonAdapter(LanguageAdapter):
    language = "python"
    extensions = (".py",)

    def parse(self, path: Path, source: str) -> list[IRNode]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        visitor = _PythonVisitor(str(path), source)
        visitor.visit(tree)
        return visitor.nodes


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, file: str, source: str) -> None:
        self.file = file
        self.source = source
        self.nodes: list[IRNode] = []
        self.imports: dict[str, str] = {}
        self.aliases: dict[str, str] = {}
        self.func_stack: list[str] = []
        self.class_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.func_stack.append(node.name)
        self.generic_visit(node)
        self.func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.imports[name] = alias.name
            self.aliases[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.imports[local] = f"{module}.{alias.name}" if module else alias.name
            self.aliases[local] = self.imports[local]
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        value_name = self._expr_name(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name) and value_name:
                self.aliases[target.id] = value_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._expr_name(node.func)
        args = [self._literal(a) for a in node.args]
        keywords = {kw.arg: self._literal(kw.value) for kw in node.keywords if kw.arg}
        self.nodes.append(
            IRNode(
                language="python",
                file=self.file,
                line=getattr(node, "lineno", 1),
                column=getattr(node, "col_offset", 0) + 1,
                kind="call",
                callee=callee,
                args=args,
                keywords=keywords,
                function=self.func_stack[-1] if self.func_stack else None,
                class_name=self.class_stack[-1] if self.class_stack else None,
                snippet=snippet_at(self.source, getattr(node, "lineno", 1)),
                resolved_name=callee,
                imports=dict(self.imports),
                source_text=self.source,
            )
        )
        self.generic_visit(node)

    def _expr_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{self._expr_name(node.value)}.{node.attr}"
        if isinstance(node, ast.Call):
            return self._expr_name(node.func)
        if isinstance(node, ast.Subscript):
            return self._expr_name(node.value)
        return type(node).__name__

    def _literal(self, node: ast.AST):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return self._expr_name(node)
        try:
            return ast.unparse(node)
        except Exception:
            return None

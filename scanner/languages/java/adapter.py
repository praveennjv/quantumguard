"""Java adapter using javalang AST."""

from __future__ import annotations

from pathlib import Path

import javalang

from scanner.ir import IRNode
from scanner.languages.base import LanguageAdapter, snippet_at


class JavaAdapter(LanguageAdapter):
    language = "java"
    extensions = (".java",)

    def parse(self, path: Path, source: str) -> list[IRNode]:
        try:
            tree = javalang.parse.parse(source)
        except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError, IndexError):
            return []
        nodes: list[IRNode] = []
        imports: dict[str, str] = {}
        for imp in tree.imports or []:
            path_name = imp.path
            simple = path_name.split(".")[-1]
            imports[simple] = path_name

        for _, class_decl in tree.filter(javalang.tree.ClassDeclaration):
            class_name = class_decl.name
            for method in class_decl.methods or []:
                self._walk_method(path, source, class_name, method, imports, nodes)
        for _, enum_decl in tree.filter(javalang.tree.EnumDeclaration):
            for method in enum_decl.methods or []:
                self._walk_method(path, source, enum_decl.name, method, imports, nodes)
        return nodes

    def _walk_method(self, path, source, class_name, method, imports, nodes) -> None:
        method_name = method.name
        if not method.body:
            return
        for _, invocation in method.filter(javalang.tree.MethodInvocation):
            line = invocation.position.line if invocation.position else 1
            qualifier = invocation.qualifier or ""
            name = invocation.member
            callee = f"{qualifier}.{name}" if qualifier else name
            args = [_java_arg(a) for a in invocation.arguments or []]
            nodes.append(
                IRNode(
                    language="java",
                    file=str(path),
                    line=line,
                    column=invocation.position.column if invocation.position else 1,
                    kind="call",
                    callee=callee,
                    args=args,
                    function=method_name,
                    class_name=class_name,
                    snippet=snippet_at(source, line),
                    resolved_name=callee,
                    imports=dict(imports),
                    source_text=source,
                )
            )
        for _, creator in method.filter(javalang.tree.ClassCreator):
            line = creator.position.line if creator.position else 1
            tname = getattr(creator.type, "name", None) or "unknown"
            args = [_java_arg(a) for a in creator.arguments or []]
            nodes.append(
                IRNode(
                    language="java",
                    file=str(path),
                    line=line,
                    column=creator.position.column if creator.position else 1,
                    kind="construct",
                    callee=tname,
                    args=args,
                    function=method_name,
                    class_name=class_name,
                    snippet=snippet_at(source, line),
                    resolved_name=tname,
                    imports=dict(imports),
                    source_text=source,
                )
            )


def _java_arg(arg):
    if isinstance(arg, javalang.tree.Literal):
        val = arg.value
        if isinstance(val, str) and len(val) >= 2 and val[0] in {'"', "'"}:
            return val[1:-1]
        try:
            return int(val)
        except (TypeError, ValueError):
            return val
    if isinstance(arg, javalang.tree.MemberReference):
        return arg.member
    if isinstance(arg, javalang.tree.MethodInvocation):
        q = arg.qualifier or ""
        return f"{q}.{arg.member}" if q else arg.member
    return None

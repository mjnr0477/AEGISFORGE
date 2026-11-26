"""Conservative, intra-scope source-to-sink analysis for Python ASTs.

This intentionally supports only simple local assignment propagation. It is a
candidate-finding engine, not a complete taint analysis or proof of exploitability.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .analyzers import sanitize_evidence
from .models import Finding
from .rules import RULE_MAP

SOURCE_PREFIXES = (
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.headers",
    "request.cookies",
    "request.data",
    "request.query_params",
    "request.path_params",
    "request.body",
    "request.url",
    "request.GET",
    "request.POST",
    "request.META",
    "request.COOKIES",
    "request.get_json",
    "request.get_data",
    "sys.argv",
)
SOURCE_CALLS = {"input", "raw_input"}
DYNAMIC_SINKS = {"eval", "exec", "builtins.eval", "builtins.exec"}
SUBPROCESS_SINKS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}
SHELL_COMMAND_SINKS = {"os.system", "os.popen"}

class _FlowVisitor(ast.NodeVisitor):
    def __init__(self, source: str, path: str) -> None:
        self.path = path
        self.lines = source.splitlines()
        self.tainted_names: set[str] = set()
        self.taint_sources: dict[str, set[int]] = {}
        self.aliases: dict[str, str] = {}
        self.scope: list[str] = []
        self.findings: list[Finding] = []

    @staticmethod
    def _dotted_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = _FlowVisitor._dotted_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Call):
            return _FlowVisitor._dotted_name(node.func)
        return ""

    def _canonical_name(self, node: ast.AST) -> str:
        name = self._dotted_name(node)
        if not name:
            return ""
        first, dot, rest = name.partition(".")
        replacement = self.aliases.get(first, first)
        return replacement + (dot + rest if dot else "")

    def _is_source_name(self, name: str) -> bool:
        return any(name == prefix or name.startswith(prefix + ".") for prefix in SOURCE_PREFIXES)

    def _taint_origins(self, node: ast.AST | None) -> set[int]:
        """Return source line numbers that can reach this expression."""
        if node is None or isinstance(node, ast.Lambda):
            # A lambda body is evaluated only when invoked, not when assigned.
            # Sinks inside the body are still visited independently by NodeVisitor.
            return set()
        if isinstance(node, ast.Name):
            return set(self.taint_sources.get(node.id, set()))
        if isinstance(node, ast.Attribute):
            if self._is_source_name(self._canonical_name(node)):
                return {max(1, getattr(node, "lineno", 1))}
            return self._taint_origins(node.value)
        if isinstance(node, ast.Call):
            function = self._canonical_name(node.func)
            if function in SOURCE_CALLS or self._is_source_name(function):
                return {max(1, getattr(node, "lineno", 1))}
        if isinstance(node, ast.Lambda):
            # The callable is not tainted merely because its body reads untrusted input.
            return set()
        origins: set[int] = set()
        for child in ast.iter_child_nodes(node):
            origins.update(self._taint_origins(child))
        return origins

    def _is_tainted(self, node: ast.AST | None) -> bool:
        return bool(self._taint_origins(node))

    def _assign_target(self, target: ast.AST, origins: set[int]) -> None:
        if isinstance(target, ast.Name):
            if origins:
                self.tainted_names.add(target.id)
                self.taint_sources[target.id] = set(origins)
            else:
                self.tainted_names.discard(target.id)
                self.taint_sources.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign_target(item, origins)

    def _add(
        self,
        rule_id: str,
        node: ast.AST,
        sink_name: str,
        source_lines: set[int],
        confidence: str = "medium",
    ) -> None:
        rule = RULE_MAP[rule_id]
        line_number = max(1, getattr(node, "lineno", 1))
        evidence = self.lines[line_number - 1].strip() if line_number <= len(self.lines) else "source expression"
        evidence = sanitize_evidence(evidence)
        caller = ".".join(self.scope) or "module scope"
        source_refs = ", ".join(str(item) for item in sorted(source_lines))
        message = f"Potential flow from input source line {source_refs} to {sink_name} in {caller}."
        self.findings.append(Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            title=rule.title,
            message=message,
            path=self.path,
            line=line_number,
            column=max(1, getattr(node, "col_offset", 0) + 1),
            evidence=evidence,
            remediation=rule.remediation,
            confidence=confidence,
            cwe=rule.cwe,
        ))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "flask":
            for item in node.names:
                if item.name == "request":
                    self.aliases[item.asname or item.name] = "request"
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            if item.name == "flask.request":
                self.aliases[item.asname or item.name] = "request"
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        previous_taint = self.tainted_names
        previous_sources = self.taint_sources
        self.tainted_names = set()
        self.taint_sources = {}
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
        self.tainted_names = previous_taint
        self.taint_sources = previous_sources

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous_taint = self.tainted_names
        previous_sources = self.taint_sources
        self.tainted_names = set()
        self.taint_sources = {}
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
        self.tainted_names = previous_taint
        self.taint_sources = previous_sources

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        previous_taint = self.tainted_names
        previous_sources = self.taint_sources
        self.tainted_names = set()
        self.taint_sources = {}
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
        self.tainted_names = previous_taint
        self.taint_sources = previous_sources

    def visit_Lambda(self, node: ast.Lambda) -> None:
        previous_taint = self.tainted_names
        previous_sources = self.taint_sources
        self.tainted_names = set()
        self.taint_sources = {}
        self.generic_visit(node)
        self.tainted_names = previous_taint
        self.taint_sources = previous_sources

    def visit_Assign(self, node: ast.Assign) -> None:
        origins = self._taint_origins(node.value)
        for target in node.targets:
            self._assign_target(target, origins)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        origins = self._taint_origins(node.value)
        self._assign_target(node.target, origins)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        origins = self._taint_origins(node.target) | self._taint_origins(node.value)
        self._assign_target(node.target, origins)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._assign_target(node.target, self._taint_origins(node.iter))
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._assign_target(node.target, self._taint_origins(node.iter))
        self.generic_visit(node)

    def _first_argument_origins(self, node: ast.Call, keyword_names: tuple[str, ...] = ()) -> set[int]:
        if node.args:
            return self._taint_origins(node.args[0])
        origins: set[int] = set()
        for keyword in node.keywords:
            if keyword.arg in keyword_names:
                origins.update(self._taint_origins(keyword.value))
        return origins

    def visit_Call(self, node: ast.Call) -> None:
        function = self._canonical_name(node.func)

        if function in DYNAMIC_SINKS:
            origins = self._first_argument_origins(node, ("source",))
            if origins:
                self._add("AF-FLOW-001", node, f"{function}()", origins)
        elif function in SUBPROCESS_SINKS:
            shell_enabled = any(
                item.arg == "shell" and isinstance(item.value, ast.Constant) and item.value.value is True
                for item in node.keywords
            )
            origins = self._first_argument_origins(node, ("args",))
            if shell_enabled and origins:
                self._add("AF-FLOW-002", node, f"{function}(shell=True)", origins)
        elif function in SHELL_COMMAND_SINKS:
            origins = self._first_argument_origins(node)
            if origins:
                self._add("AF-FLOW-002", node, f"{function}()", origins)
        elif function.endswith(".execute"):
            origins = self._first_argument_origins(node, ("operation",))
            if origins:
                self._add("AF-FLOW-003", node, f"{function}() query text", origins)

        self.generic_visit(node)

def analyze_python_flows(source: str, relative_path: str) -> list[Finding]:
    """Return candidate data-flow findings; SyntaxError is intentionally raised."""
    tree = ast.parse(source, filename=relative_path)
    visitor = _FlowVisitor(source, relative_path)
    visitor.visit(tree)
    return visitor.findings

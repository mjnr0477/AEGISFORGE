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

    def _is_tainted(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names
        if isinstance(node, ast.Attribute):
            return self._is_source_name(self._canonical_name(node))
        if isinstance(node, ast.Call):
            function = self._canonical_name(node.func)
            if function in SOURCE_CALLS or self._is_source_name(function):
                return True
            if any(self._is_tainted(argument) for argument in node.args):
                return True
            return any(self._is_tainted(keyword.value) for keyword in node.keywords)
        return any(self._is_tainted(child) for child in ast.iter_child_nodes(node))

    def _assign_target(self, target: ast.AST, is_tainted: bool) -> None:
        if isinstance(target, ast.Name):
            if is_tainted:
                self.tainted_names.add(target.id)
            else:
                self.tainted_names.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign_target(item, is_tainted)

    def _add(self, rule_id: str, node: ast.AST, sink_name: str, confidence: str = "medium") -> None:
        rule = RULE_MAP[rule_id]
        line_number = max(1, getattr(node, "lineno", 1))
        evidence = self.lines[line_number - 1].strip() if line_number <= len(self.lines) else "source expression"
        evidence = sanitize_evidence(evidence)
        caller = ".".join(self.scope) or "module scope"
        message = f"A value derived from request or interactive input reaches {sink_name} in {caller}."
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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous_taint = self.tainted_names
        self.tainted_names = set()
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
        self.tainted_names = previous_taint

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        previous_taint = self.tainted_names
        self.tainted_names = set()
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
        self.tainted_names = previous_taint

    def visit_Lambda(self, node: ast.Lambda) -> None:
        previous_taint = self.tainted_names
        self.tainted_names = set()
        self.generic_visit(node)
        self.tainted_names = previous_taint

    def visit_Assign(self, node: ast.Assign) -> None:
        tainted = self._is_tainted(node.value)
        for target in node.targets:
            self._assign_target(target, tainted)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        tainted = self._is_tainted(node.value)
        self._assign_target(node.target, tainted)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        tainted = self._is_tainted(node.target) or self._is_tainted(node.value)
        self._assign_target(node.target, tainted)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._assign_target(node.target, self._is_tainted(node.iter))
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._assign_target(node.target, self._is_tainted(node.iter))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        function = self._canonical_name(node.func)
        positional_tainted = any(self._is_tainted(argument) for argument in node.args)
        keyword_tainted = any(self._is_tainted(keyword.value) for keyword in node.keywords)
        arguments_tainted = positional_tainted or keyword_tainted

        if function in DYNAMIC_SINKS and arguments_tainted:
            self._add("AF-FLOW-001", node, f"{function}()")
        elif function in SUBPROCESS_SINKS:
            shell_enabled = any(
                item.arg == "shell" and isinstance(item.value, ast.Constant) and item.value.value is True
                for item in node.keywords
            )
            if shell_enabled and arguments_tainted:
                self._add("AF-FLOW-002", node, f"{function}(shell=True)")
        elif function in SHELL_COMMAND_SINKS and arguments_tainted:
            self._add("AF-FLOW-002", node, f"{function}()")
        elif function.endswith(".execute") and node.args and self._is_tainted(node.args[0]):
            self._add("AF-FLOW-003", node, f"{function}() query text")

        self.generic_visit(node)

def analyze_python_flows(source: str, relative_path: str) -> list[Finding]:
    """Return candidate data-flow findings; SyntaxError is intentionally raised."""
    tree = ast.parse(source, filename=relative_path)
    visitor = _FlowVisitor(source, relative_path)
    visitor.visit(tree)
    return visitor.findings

"""Conservative, intra-scope source-to-sink analysis for Python ASTs.

This intentionally supports only simple local assignment propagation. It is a
candidate-finding engine, not a complete taint analysis or proof of exploitability.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
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

@dataclass(frozen=True, slots=True)
class _SinkFlow:
    rule_id: str
    node: ast.Call
    sink_name: str
    origins: frozenset[int]


@dataclass(frozen=True, slots=True)
class _FunctionSummary:
    parameters: tuple[str, ...]
    return_origins: frozenset[int]
    sink_flows: tuple[_SinkFlow, ...]


class _FlowVisitor(ast.NodeVisitor):
    def __init__(
        self,
        source: str,
        path: str,
        function_summaries: dict[str, _FunctionSummary] | None = None,
    ) -> None:
        self.path = path
        self.lines = source.splitlines()
        self.function_summaries = function_summaries or {}
        self.sink_flows: list[_SinkFlow] = []
        self.return_origins: set[int] = set()
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
        # import flask as f; f.request.args is equivalent to the common
        # from flask import request spelling.
        if name.startswith("flask.request."):
            name = name[len("flask."):]
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
            summary = self.function_summaries.get(function) if "." not in function else None
            if summary is not None:
                return self._substitute_origins(summary.return_origins, node, summary.parameters)
        origins: set[int] = set()
        for child in ast.iter_child_nodes(node):
            origins.update(self._taint_origins(child))
        return origins

    def _is_tainted(self, node: ast.AST | None) -> bool:
        return bool(self._taint_origins(node))

    def _substitute_origins(
        self,
        origins: frozenset[int] | set[int],
        call: ast.Call,
        parameters: tuple[str, ...],
    ) -> set[int]:
        """Replace negative parameter markers with taint from call-site arguments."""
        arguments: dict[str, ast.AST] = {}
        for name, value in zip(parameters, call.args):
            if not isinstance(value, ast.Starred):
                arguments[name] = value
        for keyword in call.keywords:
            if keyword.arg in parameters:
                arguments[keyword.arg] = keyword.value
        resolved: set[int] = set()
        for origin in origins:
            if origin > 0:
                resolved.add(origin)
            elif origin < 0:
                index = -origin - 1
                if index < len(parameters):
                    argument = arguments.get(parameters[index])
                    if argument is not None:
                        resolved.update(self._taint_origins(argument))
        return resolved

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
        self.sink_flows.append(_SinkFlow(
            rule_id=rule_id,
            node=node if isinstance(node, ast.Call) else ast.Call(func=ast.Name(id=sink_name), args=[], keywords=[]),
            sink_name=sink_name,
            origins=frozenset(source_lines),
        ))
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
        module = node.module or ""
        for item in node.names:
            local_name = item.asname or item.name
            if module == "flask" and item.name == "request":
                canonical_name = "request"
            else:
                canonical_name = f"{module}.{item.name}" if module else item.name
            self.aliases[local_name] = canonical_name
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            if item.asname:
                local_name = item.asname
                canonical_name = "request" if item.name == "flask.request" else item.name
            else:
                local_name = item.name.split(".", 1)[0]
                canonical_name = local_name
            self.aliases[local_name] = canonical_name
        self.generic_visit(node)

    def _visit_nested_scope(self, node: ast.AST, label: str) -> None:
        previous_taint = self.tainted_names
        previous_sources = self.taint_sources
        previous_aliases = self.aliases.copy()
        previous_returns = self.return_origins
        previous_flows = self.sink_flows
        self.tainted_names = set()
        self.taint_sources = {}
        self.return_origins = set()
        self.sink_flows = []
        self.scope.append(label)
        try:
            self.generic_visit(node)
        finally:
            self.scope.pop()
            self.tainted_names = previous_taint
            self.taint_sources = previous_sources
            self.aliases = previous_aliases
            self.return_origins = previous_returns
            self.sink_flows = previous_flows

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_nested_scope(node, node.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_nested_scope(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_nested_scope(node, node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_nested_scope(node, "<lambda>")

    def visit_Return(self, node: ast.Return) -> None:
        self.return_origins.update(self._taint_origins(node.value))
        self.generic_visit(node)

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

        summary = self.function_summaries.get(function) if "." not in function else None
        if summary is not None:
            for flow in summary.sink_flows:
                origins = self._substitute_origins(flow.origins, node, summary.parameters)
                if origins:
                    self._add(flow.rule_id, flow.node, flow.sink_name, origins)

        self.generic_visit(node)


def _function_parameters(node: ast.FunctionDef) -> tuple[str, ...]:
    args = node.args
    return tuple(
        item.arg for item in (*args.posonlyargs, *args.args, *args.kwonlyargs)
    )


def _module_import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.asname:
                    aliases[item.asname] = item.name
                else:
                    bound = item.name.split(".", 1)[0]
                    aliases[bound] = bound
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for item in node.names:
                local = item.asname or item.name
                if module == "flask" and item.name == "request":
                    aliases[local] = "request"
                else:
                    aliases[local] = f"{module}.{item.name}" if module else item.name
    return aliases


def _summarize_function(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    source: str,
    relative_path: str,
    module_aliases: dict[str, str],
    summaries: dict[str, _FunctionSummary],
) -> _FunctionSummary:
    visitor = _FlowVisitor(source, relative_path, summaries)
    visitor.aliases.update(module_aliases)
    parameters = _function_parameters(function)
    visitor.tainted_names.update(parameters)
    visitor.taint_sources.update({
        name: {-(index + 1)} for index, name in enumerate(parameters)
    })
    visitor.scope.append(function.name)
    for statement in function.body:
        visitor.visit(statement)

    unique_flows: dict[tuple[str, int, str, frozenset[int]], _SinkFlow] = {}
    for flow in visitor.sink_flows:
        key = (
            flow.rule_id,
            max(1, getattr(flow.node, "lineno", 1)),
            flow.sink_name,
            flow.origins,
        )
        unique_flows[key] = flow
    return _FunctionSummary(
        parameters=parameters,
        return_origins=frozenset(visitor.return_origins),
        sink_flows=tuple(unique_flows.values()),
    )


def _local_function_summaries(
    tree: ast.Module,
    source: str,
    relative_path: str,
) -> dict[str, _FunctionSummary]:
    # Only unambiguous synchronous module-level functions are summarized.
    # Async functions, methods, nested functions, dynamic dispatch, and
    # star-argument binding remain out of scope.
    candidates = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
    ]
    counts: dict[str, int] = {}
    for function in candidates:
        counts[function.name] = counts.get(function.name, 0) + 1
    functions = {node.name: node for node in candidates if counts[node.name] == 1}
    if not functions:
        return {}

    aliases = _module_import_aliases(tree)
    summaries: dict[str, _FunctionSummary] = {}
    # A bounded fixed-point pass propagates summaries through short local helper
    # chains without recursively executing or importing any scanned code.
    max_rounds = min(len(functions) + 1, 12)
    for _ in range(max_rounds):
        changed = False
        for name, function in functions.items():
            current = _summarize_function(function, source, relative_path, aliases, summaries)
            if summaries.get(name) != current:
                summaries[name] = current
                changed = True
        if not changed:
            break
    return summaries


def analyze_python_flows(source: str, relative_path: str) -> list[Finding]:
    """Return conservative intra- and bounded interprocedural flow findings."""
    tree = ast.parse(source, filename=relative_path)
    summaries = _local_function_summaries(tree, source, relative_path)
    visitor = _FlowVisitor(source, relative_path, summaries)
    visitor.visit(tree)

    unique: dict[tuple[str, str, int, str], Finding] = {}
    for finding in visitor.findings:
        key = (finding.rule_id, finding.path, finding.line, finding.message)
        unique[key] = finding
    return list(unique.values())

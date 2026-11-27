"""Read-only Python project structure index built with the standard-library AST."""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .scanner import collect_files, read_source_file

@dataclass(frozen=True, slots=True)
class ImportRecord:
    module: str
    imported_name: str | None
    alias: str | None
    line: int
    relative_level: int = 0
    scope: str | None = None

@dataclass(frozen=True, slots=True)
class SymbolRecord:
    name: str
    qualified_name: str
    kind: str
    line: int
    end_line: int
    parent: str | None
    parameters: int

@dataclass(frozen=True, slots=True)
class CallRecord:
    caller: str
    callee: str
    line: int
    column: int

@dataclass(frozen=True, slots=True)
class DependencyRecord:
    source_module: str
    target_module: str
    line: int
    import_kind: str
    imported_name: str | None
    alias: str | None
    resolution: str


@dataclass(frozen=True, slots=True)
class CrossFileCallRecord:
    source_module: str
    caller: str
    callee: str
    target_module: str
    target_symbol: str
    line: int
    column: int
    resolution: str


@dataclass(frozen=True, slots=True)
class ModuleRecord:
    module: str
    path: str
    imports: tuple[ImportRecord, ...]
    symbols: tuple[SymbolRecord, ...]
    calls: tuple[CallRecord, ...]

class _ScopeBindingCollector(ast.NodeVisitor):
    """Collect names bound in one scope while leaving nested scopes opaque."""

    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    @staticmethod
    def _root_name(node: ast.AST) -> str | None:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            root = self._root_name(node)
            if root:
                self.names.add(root)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            root = self._root_name(node)
            if root:
                self.names.add(root)
        self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> None:
        self.names.add(node.arg)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.names.add(item.asname or item.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            if item.name != "*":
                self.names.add(item.asname or item.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global) -> None:
        self.names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.names.update(node.names)


def _scope_bindings(node: ast.AST) -> set[str]:
    collector = _ScopeBindingCollector()
    arguments = getattr(node, "args", None)
    if arguments is not None:
        for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs):
            collector.names.add(argument.arg)
        if arguments.vararg is not None:
            collector.names.add(arguments.vararg.arg)
        if arguments.kwarg is not None:
            collector.names.add(arguments.kwarg.arg)
    body = getattr(node, "body", [])
    if isinstance(body, list):
        for statement in body:
            collector.visit(statement)
    return collector.names


class _ModuleRebindingCollector(_ScopeBindingCollector):
    """Collect module-level rebinding without counting import declarations."""

    def visit_Import(self, node: ast.Import) -> None:
        return

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        return


def _module_rebound_names(tree: ast.Module) -> set[str]:
    collector = _ModuleRebindingCollector()
    for statement in tree.body:
        collector.visit(statement)
    return collector.names


class _ModuleVisitor(ast.NodeVisitor):
    def __init__(self, module_rebound_names: set[str] | None = None) -> None:
        self.scope: list[str] = []
        self.module_rebound_names = module_rebound_names or set()
        self.imports: list[ImportRecord] = []
        self.symbols: list[SymbolRecord] = []
        self.calls: list[CallRecord] = []
        self.scope_bindings: list[set[str]] = []
        self.call_shadowed_names: dict[tuple[int, int], frozenset[str]] = {}

    @staticmethod
    def dotted_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = _ModuleVisitor.dotted_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        if isinstance(node, ast.Call):
            return _ModuleVisitor.dotted_name(node.func)
        if isinstance(node, ast.Subscript):
            return _ModuleVisitor.dotted_name(node.value)
        return ""

    def _record_symbol(self, node: ast.AST, kind: str, name: str, parameters: int) -> None:
        parent = ".".join(self.scope) or None
        qualified = ".".join([*self.scope, name])
        self.symbols.append(SymbolRecord(
            name=name,
            qualified_name=qualified,
            kind=kind,
            line=getattr(node, "lineno", 1),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
            parent=parent,
            parameters=parameters,
        ))
        self.scope.append(name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.scope_bindings.append(_scope_bindings(node))
        else:
            self.scope_bindings.append(set())
        self.generic_visit(node)
        self.scope_bindings.pop()
        self.scope.pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(ImportRecord(
                module=alias.name,
                imported_name=None,
                alias=alias.asname,
                line=node.lineno,
                scope=".".join(self.scope) or None,
            ))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.imports.append(ImportRecord(
                module=module,
                imported_name=alias.name,
                alias=alias.asname,
                line=node.lineno,
                relative_level=node.level,
                scope=".".join(self.scope) or None,
            ))

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._record_symbol(node, "class", node.name, 0)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        parameters = len(node.args.posonlyargs) + len(node.args.args) + len(node.args.kwonlyargs)
        if node.args.vararg:
            parameters += 1
        if node.args.kwarg:
            parameters += 1
        self._record_symbol(node, "function", node.name, parameters)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        parameters = len(node.args.posonlyargs) + len(node.args.args) + len(node.args.kwonlyargs)
        if node.args.vararg:
            parameters += 1
        if node.args.kwarg:
            parameters += 1
        self._record_symbol(node, "async_function", node.name, parameters)

    def visit_Call(self, node: ast.Call) -> None:
        callee = self.dotted_name(node.func)
        if callee:
            line = getattr(node, "lineno", 1)
            column = getattr(node, "col_offset", 0) + 1
            self.calls.append(CallRecord(
                caller=".".join(self.scope) or "<module>",
                callee=callee,
                line=line,
                column=column,
            ))
            shadowed: set[str] = set(self.module_rebound_names)
            for names in self.scope_bindings:
                shadowed.update(names)
            self.call_shadowed_names[(line, column)] = frozenset(shadowed)
        self.generic_visit(node)

@dataclass(slots=True)
class ProjectMap:
    project: str
    scanned_files: int
    skipped_files: int
    modules: list[ModuleRecord]
    warnings: list[str]
    dependencies: list[DependencyRecord] = field(default_factory=list)
    cross_file_calls: list[CrossFileCallRecord] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        return {
            "modules": len(self.modules),
            "imports": sum(len(module.imports) for module in self.modules),
            "classes": sum(symbol.kind == "class" for module in self.modules for symbol in module.symbols),
            "functions": sum(symbol.kind in {"function", "async_function"} for module in self.modules for symbol in module.symbols),
            "calls": sum(len(module.calls) for module in self.modules),
            "dependency_edges": len(self.dependencies),
            "cross_file_calls": len(self.cross_file_calls),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "AegisForge",
            "operation": "project_map",
            "project": self.project,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "summary": self.summary,
            "modules": [asdict(module) for module in self.modules],
            "dependencies": [asdict(item) for item in self.dependencies],
            "cross_file_calls": [asdict(item) for item in self.cross_file_calls],
            "warnings": list(self.warnings),
        }

def _module_name(relative_path: str) -> str:
    path = Path(relative_path)
    without_suffix = path.with_suffix("")
    parts = list(without_suffix.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "__init__"

def _package_parts(module: ModuleRecord) -> list[str]:
    """Return the import package containing this file, without importing it."""
    parts = [part for part in module.module.split(".") if part]
    if Path(module.path).name == "__init__.py":
        return [] if parts == ["__init__"] else parts
    return parts[:-1]


def _absolute_import_base(importer: ModuleRecord, item: ImportRecord) -> str | None:
    if item.relative_level <= 0:
        return item.module

    package = _package_parts(importer)
    if item.relative_level > len(package):
        return None
    ascend = item.relative_level - 1
    parts = package[:len(package) - ascend]
    if item.module:
        parts.extend(part for part in item.module.split(".") if part)
    return ".".join(parts)


def _build_dependencies(modules: list[ModuleRecord]) -> list[DependencyRecord]:
    """Resolve import references only to Python modules in this scanned project.

    A from-import can refer to a package attribute or a sibling submodule.
    Keep the package edge direct and label a matching submodule as possible.
    """
    module_counts: dict[str, int] = {}
    for module in modules:
        module_counts[module.module] = module_counts.get(module.module, 0) + 1
    # A file and a same-named package can collide; do not choose one arbitrarily.
    known_modules = {name for name, count in module_counts.items() if count == 1}
    dependencies: list[DependencyRecord] = []

    for importer in modules:
        if importer.module not in known_modules:
            continue
        for item in importer.imports:
            base = _absolute_import_base(importer, item)
            if base is None:
                continue
            if item.imported_name is None:
                if base and base in known_modules:
                    dependencies.append(DependencyRecord(
                        source_module=importer.module,
                        target_module=base,
                        line=item.line,
                        import_kind="import",
                        imported_name=None,
                        alias=item.alias,
                        resolution="direct",
                    ))
                continue

            if base and base in known_modules:
                dependencies.append(DependencyRecord(
                    source_module=importer.module,
                    target_module=base,
                    line=item.line,
                    import_kind="from",
                    imported_name=item.imported_name,
                    alias=item.alias,
                    resolution="direct",
                ))

            if item.imported_name != "*":
                candidate = ".".join(part for part in (base, item.imported_name) if part)
                if candidate and candidate != base and candidate in known_modules:
                    dependencies.append(DependencyRecord(
                        source_module=importer.module,
                        target_module=candidate,
                        line=item.line,
                        import_kind="from",
                        imported_name=item.imported_name,
                        alias=item.alias,
                        resolution="possible_submodule",
                    ))

    return sorted(
        dependencies,
        key=lambda item: (
            item.source_module, item.line, item.target_module,
            item.resolution, item.imported_name or "",
        ),
    )


def _build_cross_file_calls(
    modules: list[ModuleRecord],
    call_shadowed_names: dict[str, dict[tuple[int, int], frozenset[str]]],
) -> list[CrossFileCallRecord]:
    """Resolve calls through explicit local imports; never guess dynamic dispatch."""
    module_counts: dict[str, int] = {}
    for module in modules:
        module_counts[module.module] = module_counts.get(module.module, 0) + 1
    known_modules = {name for name, count in module_counts.items() if count == 1}
    symbols_by_module: dict[str, dict[str, list[SymbolRecord]]] = {}
    for module in modules:
        if module.module not in known_modules:
            continue
        by_name: dict[str, list[SymbolRecord]] = {}
        for symbol in module.symbols:
            by_name.setdefault(symbol.qualified_name, []).append(symbol)
        symbols_by_module[module.module] = by_name

    results: list[CrossFileCallRecord] = []
    for source in modules:
        if source.module not in known_modules:
            continue

        # Count every module-scope import binding, including external imports.
        # An unresolved import can still overwrite a name used by a local import.
        local_binding_counts: dict[str, int] = {}
        has_star_import = False
        for item in source.imports:
            if item.scope is not None:
                continue
            if item.imported_name == "*":
                has_star_import = True
                continue
            local_name = (
                item.alias or item.module.split(".", 1)[0]
                if item.imported_name is None
                else item.alias or item.imported_name
            )
            if local_name:
                local_binding_counts[local_name] = local_binding_counts.get(local_name, 0) + 1
        ambiguous_local_bindings = {
            name for name, count in local_binding_counts.items() if count > 1
        }

        # Each binding maps a local expression prefix to an imported module or symbol.
        bindings: list[dict[str, str]] = []
        for item in source.imports:
            if item.scope is not None:
                continue
            base = _absolute_import_base(source, item)
            if base is None:
                continue
            if item.imported_name is None:
                if base not in known_modules:
                    continue
                local_prefix = item.alias or item.module.split(".", 1)[0]
                access_prefix = item.alias or item.module
                if not local_prefix or not access_prefix:
                    continue
                bindings.append({
                    "local_prefix": local_prefix,
                    "access_prefix": access_prefix,
                    "target_module": base,
                    "target_symbol": "",
                    "kind": "module",
                    "resolution": "direct",
                })
                continue

            if item.imported_name == "*":
                continue
            local_name = item.alias or item.imported_name
            submodule = ".".join(part for part in (base, item.imported_name) if part)
            has_package = base in known_modules
            has_symbol = (
                has_package
                and bool(symbols_by_module.get(base, {}).get(item.imported_name, []))
            )
            has_submodule = submodule in known_modules and submodule != base
            if has_symbol:
                bindings.append({
                    "local_prefix": local_name,
                    "access_prefix": local_name,
                    "target_module": base,
                    "target_symbol": item.imported_name,
                    "kind": "symbol",
                    "resolution": "ambiguous" if has_submodule else "direct",
                })
            elif has_submodule:
                bindings.append({
                    "local_prefix": local_name,
                    "access_prefix": local_name,
                    "target_module": submodule,
                    "target_symbol": "",
                    "kind": "module",
                    "resolution": "possible_submodule",
                })

        if has_star_import:
            continue

        shadowed_calls = call_shadowed_names.get(source.path, {})
        for call in source.calls:
            call_shadowed = shadowed_calls.get((call.line, call.column), frozenset())
            candidates: list[CrossFileCallRecord] = []
            for binding in bindings:
                local_prefix = binding["local_prefix"]
                if local_prefix in call_shadowed or local_prefix in ambiguous_local_bindings:
                    continue
                access_prefix = binding["access_prefix"]

                target_module = binding["target_module"]
                binding_kind = binding["kind"]
                binding_resolution = binding["resolution"]
                target_symbol_prefix = binding["target_symbol"]

                if binding_kind == "symbol":
                    if call.callee == access_prefix:
                        symbol_names = [target_symbol_prefix]
                    elif call.callee.startswith(access_prefix + "."):
                        suffix = call.callee[len(access_prefix) + 1:]
                        symbol_names = [target_symbol_prefix + "." + suffix]
                    else:
                        continue
                    for symbol_name in symbol_names:
                        matches = symbols_by_module.get(target_module, {}).get(symbol_name, [])
                        if len(matches) == 1:
                            candidates.append(CrossFileCallRecord(
                                source_module=source.module,
                                caller=call.caller,
                                callee=call.callee,
                                target_module=target_module,
                                target_symbol=symbol_name,
                                line=call.line,
                                column=call.column,
                                resolution=binding_resolution,
                            ))
                    continue

                if not call.callee.startswith(access_prefix + "."):
                    continue
                suffix = call.callee[len(access_prefix) + 1:].split(".")
                # Prefer the deepest uniquely indexed submodule whose remainder
                # names exactly one symbol. Shorter matches are not inferred.
                matches_for_binding: list[tuple[int, str, str]] = []
                for depth in range(len(suffix)):
                    candidate_module = ".".join([target_module, *suffix[:depth]]) if depth else target_module
                    symbol_name = ".".join(suffix[depth:])
                    if candidate_module not in known_modules or not symbol_name:
                        continue
                    if len(symbols_by_module.get(candidate_module, {}).get(symbol_name, [])) == 1:
                        matches_for_binding.append((depth, candidate_module, symbol_name))
                if matches_for_binding:
                    deepest = max(item[0] for item in matches_for_binding)
                    deepest_matches = [item for item in matches_for_binding if item[0] == deepest]
                    if len(deepest_matches) == 1:
                        _, resolved_module, resolved_symbol = deepest_matches[0]
                        candidates.append(CrossFileCallRecord(
                            source_module=source.module,
                            caller=call.caller,
                            callee=call.callee,
                            target_module=resolved_module,
                            target_symbol=resolved_symbol,
                            line=call.line,
                            column=call.column,
                            resolution=binding_resolution,
                        ))

            # Multiple import bindings that could explain the same call are not
            # collapsed into an arbitrary target.
            unique = {
                (item.target_module, item.target_symbol, item.resolution): item
                for item in candidates
            }
            if len(unique) == 1:
                resolved = next(iter(unique.values()))
                if resolved.target_module != source.module:
                    results.append(resolved)

    return sorted(
        results,
        key=lambda item: (
            item.source_module, item.line, item.column,
            item.target_module, item.target_symbol,
        ),
    )


def build_project_map(target: str | Path) -> ProjectMap:
    """Build a bounded structural index of Python files without importing them."""
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"target does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"target must be a directory: {root}")

    paths, skipped, warnings = collect_files(root)
    modules: list[ModuleRecord] = []
    call_shadowed_names: dict[str, dict[tuple[int, int], frozenset[str]]] = {}
    scanned = 0
    for path in paths:
        if path.suffix.lower() not in {".py", ".pyw"}:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            source = read_source_file(path)
        except (OSError, ValueError) as exc:
            skipped += 1
            warnings.append(f"{relative}: {exc}")
            continue
        scanned += 1
        try:
            tree = ast.parse(source, filename=relative)
        except SyntaxError as exc:
            location = f" at line {exc.lineno}" if exc.lineno else ""
            warnings.append(f"{relative}: Python syntax error{location}; structural index skipped: {exc.msg}")
            continue
        visitor = _ModuleVisitor(_module_rebound_names(tree))
        visitor.visit(tree)
        call_shadowed_names[relative] = visitor.call_shadowed_names
        modules.append(ModuleRecord(
            module=_module_name(relative),
            path=relative,
            imports=tuple(sorted(visitor.imports, key=lambda item: (item.line, item.module, item.imported_name or ""))),
            symbols=tuple(sorted(visitor.symbols, key=lambda item: (item.line, item.qualified_name))),
            calls=tuple(sorted(visitor.calls, key=lambda item: (item.line, item.column, item.callee))),
        ))
    modules.sort(key=lambda item: item.path)
    dependencies = _build_dependencies(modules)
    cross_file_calls = _build_cross_file_calls(modules, call_shadowed_names)
    return ProjectMap(
        project=root.name,
        scanned_files=scanned,
        skipped_files=skipped,
        modules=modules,
        warnings=warnings,
        dependencies=dependencies,
        cross_file_calls=cross_file_calls,
    )

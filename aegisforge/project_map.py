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
class ModuleRecord:
    module: str
    path: str
    imports: tuple[ImportRecord, ...]
    symbols: tuple[SymbolRecord, ...]
    calls: tuple[CallRecord, ...]

class _ModuleVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope: list[str] = []
        self.imports: list[ImportRecord] = []
        self.symbols: list[SymbolRecord] = []
        self.calls: list[CallRecord] = []

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
        self.generic_visit(node)
        self.scope.pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(ImportRecord(
                module=alias.name,
                imported_name=None,
                alias=alias.asname,
                line=node.lineno,
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
            self.calls.append(CallRecord(
                caller=".".join(self.scope) or "<module>",
                callee=callee,
                line=getattr(node, "lineno", 1),
                column=getattr(node, "col_offset", 0) + 1,
            ))
        self.generic_visit(node)

@dataclass(slots=True)
class ProjectMap:
    project: str
    scanned_files: int
    skipped_files: int
    modules: list[ModuleRecord]
    warnings: list[str]
    dependencies: list[DependencyRecord] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        return {
            "modules": len(self.modules),
            "imports": sum(len(module.imports) for module in self.modules),
            "classes": sum(symbol.kind == "class" for module in self.modules for symbol in module.symbols),
            "functions": sum(symbol.kind in {"function", "async_function"} for module in self.modules for symbol in module.symbols),
            "calls": sum(len(module.calls) for module in self.modules),
            "dependency_edges": len(self.dependencies),
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


def build_project_map(target: str | Path) -> ProjectMap:
    """Build a bounded structural index of Python files without importing them."""
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"target does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"target must be a directory: {root}")

    paths, skipped, warnings = collect_files(root)
    modules: list[ModuleRecord] = []
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
        visitor = _ModuleVisitor()
        visitor.visit(tree)
        modules.append(ModuleRecord(
            module=_module_name(relative),
            path=relative,
            imports=tuple(sorted(visitor.imports, key=lambda item: (item.line, item.module, item.imported_name or ""))),
            symbols=tuple(sorted(visitor.symbols, key=lambda item: (item.line, item.qualified_name))),
            calls=tuple(sorted(visitor.calls, key=lambda item: (item.line, item.column, item.callee))),
        ))
    modules.sort(key=lambda item: item.path)
    dependencies = _build_dependencies(modules)
    return ProjectMap(
        project=root.name,
        scanned_files=scanned,
        skipped_files=skipped,
        modules=modules,
        warnings=warnings,
        dependencies=dependencies,
    )

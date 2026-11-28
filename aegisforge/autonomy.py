"""Permission-gated local tool registry and deterministic audit mission runner.

This is a workflow/execution foundation, not a general language model. Tools are
explicitly registered, local-only, and mutating actions require caller approval.
"""
from __future__ import annotations

import math
import re
import secrets
import time
from dataclasses import asdict, dataclass, field, fields, is_dataclass, replace
from pathlib import Path, PurePath
from typing import Any, Callable

from .authority import CAPABILITY_RE, AuthorityKernel
from .models import Finding, ScanResult
from .project_map import ProjectMap, build_project_map
from .repairs import RepairProposal, apply_repairs, propose_repairs
from .scanner import scan_directory

TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")

class ToolPermissionError(PermissionError):
    """Raised when a tool call is denied by an explicit permission boundary."""


class ToolApprovalRequired(ToolPermissionError):
    """Raised when a mutating operation has a grant but lacks its one-time approval."""


class ToolExecutionAuditError(RuntimeError):
    """Raised when a tool's execution outcome cannot be durably recorded."""


@dataclass(frozen=True, slots=True)
class ActionTool:
    name: str
    description: str
    handler: Callable[..., Any]
    mutates: bool = False
    capability: str | None = None
    scope_resolver: Callable[..., str] | None = None

def _freeze_tool_value(value: Any, *, depth: int, budget: dict[str, int]) -> Any:
    """Snapshot supported tool inputs so scope checks and handlers see one value.

    Mutable containers are copied into immutable equivalents. Frozen dataclasses
    are accepted only when all of their fields are themselves safely immutable.
    Arbitrary application objects are rejected rather than trusting deepcopy hooks.
    """
    budget["nodes"] += 1
    if budget["nodes"] > 50_000:
        raise ToolPermissionError("authorized tool arguments contain too many values")
    if depth > 32:
        raise ToolPermissionError("authorized tool arguments are nested too deeply")
    if value is None or type(value) in (bool, int, str, bytes):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ToolPermissionError("authorized tool arguments must not contain non-finite numbers")
        return value
    if isinstance(value, PurePath):
        return value
    if type(value) in (list, tuple):
        frozen_items = tuple(
            _freeze_tool_value(item, depth=depth + 1, budget=budget)
            for item in value
        )
        if type(value) is tuple and all(
            frozen is original for frozen, original in zip(frozen_items, value)
        ):
            return value
        return frozen_items
    if type(value) is dict:
        if len(value) > 4096:
            raise ToolPermissionError("authorized tool argument objects may contain at most 4096 keys")
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ToolPermissionError("authorized tool argument object keys must be strings")
            frozen[key] = _freeze_tool_value(item, depth=depth + 1, budget=budget)
        return MappingProxyType(frozen)
    if is_dataclass(value) and not isinstance(value, type):
        params = getattr(type(value), "__dataclass_params__", None)
        if params is None or not params.frozen:
            raise ToolPermissionError(
                f"authorized tool arguments do not accept mutable dataclass {type(value).__name__}"
            )
        changes: dict[str, Any] = {}
        for item in fields(value):
            original = getattr(value, item.name)
            frozen = _freeze_tool_value(original, depth=depth + 1, budget=budget)
            if frozen is not original:
                changes[item.name] = frozen
        if not changes:
            return value
        try:
            return replace(value, **changes)
        except (TypeError, ValueError) as exc:
            raise ToolPermissionError(
                f"could not safely snapshot dataclass {type(value).__name__}"
            ) from exc
    raise ToolPermissionError(
        f"authorized tool arguments do not support mutable value type {type(value).__name__}"
    )


def _freeze_tool_arguments(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> tuple[tuple[Any, ...], Mapping[str, Any]]:
    budget = {"nodes": 0}
    safe_args = tuple(
        _freeze_tool_value(value, depth=0, budget=budget) for value in args
    )
    safe_kwargs = _freeze_tool_value(kwargs, depth=0, budget=budget)
    return safe_args, safe_kwargs


class ToolRegistry:
    """Small explicit registry; it never imports or discovers tools dynamically."""

    def __init__(self) -> None:
        self._tools: dict[str, ActionTool] = {}

    def register(self, tool: ActionTool) -> None:
        if not isinstance(tool, ActionTool):
            raise TypeError("tool must be an ActionTool")
        if not TOOL_NAME_RE.fullmatch(tool.name):
            raise ValueError("tool name must use 2-64 lowercase letters, digits, or underscores and start with a letter")
        if not isinstance(tool.description, str) or not tool.description.strip():
            raise ValueError("tool description must not be empty")
        if not callable(tool.handler):
            raise ValueError("tool handler must be callable")
        if not isinstance(tool.mutates, bool):
            raise ValueError("tool mutates flag must be boolean")
        if tool.capability is not None and (
            not isinstance(tool.capability, str) or not CAPABILITY_RE.fullmatch(tool.capability)
        ):
            raise ValueError("tool capability must be a dotted lowercase identifier")
        if tool.scope_resolver is not None and not callable(tool.scope_resolver):
            raise ValueError("tool scope_resolver must be callable")
        if tool.name in self._tools:
            raise ValueError(f"tool is already registered: {tool.name}")
        self._tools[tool.name] = tool

    def call(self, name: str, *args: Any, approve_mutation: bool = False, **kwargs: Any) -> Any:
        """Invoke a read-only tool without policy context.

        The legacy boolean is accepted for call-site compatibility but never
        authorizes a mutation. Mutating handlers must use call_authorized(), which
        checks an exact resource grant and consumes a one-time approval token.
        """
        del approve_mutation  # A caller-controlled boolean is not an authorization.
        try:
            tool = self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown local tool: {name}") from exc
        if tool.mutates:
            raise ToolPermissionError(
                f"tool '{name}' is mutating; use call_authorized() with an exact grant "
                "and one-time approval token"
            )
        return tool.handler(*args, **kwargs)

    def call_authorized(
        self,
        name: str,
        *args: Any,
        authority: AuthorityKernel,
        subject: str,
        approval_token: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Resolve the target scope and authorize immediately before invocation.

        The resource is derived from the handler arguments, never trusted from
        a separate caller-supplied string. Tools used here must declare a scope
        resolver and a capability whose mutation classification matches.
        """
        try:
            tool = self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown local tool: {name}") from exc
        if tool.capability is None:
            raise ToolPermissionError(f"tool '{name}' has no authority capability mapping")
        if tool.scope_resolver is None:
            raise ToolPermissionError(f"tool '{name}' has no resource scope resolver")
        safe_args, safe_kwargs = _freeze_tool_arguments(args, kwargs)
        resource = tool.scope_resolver(*safe_args, **safe_kwargs)
        if (
            not isinstance(resource, str)
            or not resource.strip()
            or len(resource) > 1024
            or any(ord(char) < 32 or ord(char) == 127 for char in resource)
        ):
            raise ToolPermissionError(f"tool '{name}' resolved an invalid resource scope")
        expected_mutation = authority.capability_is_mutating(tool.capability)
        if expected_mutation is None or expected_mutation != tool.mutates:
            raise ToolPermissionError(
                f"tool '{name}' mutation classification does not match capability '{tool.capability}'"
            )
        decision = authority.authorize(
            subject=subject,
            capability=tool.capability,
            resource=resource,
            approval_token=approval_token,
        )
        if not decision.allowed:
            message = f"authority denied tool '{name}': {decision.reason}"
            if decision.reason == "approval_required":
                raise ToolApprovalRequired(message)
            raise ToolPermissionError(message)

        execution_id = secrets.token_urlsafe(24)
        start_sequence = authority.record_execution_started(
            decision=decision,
            execution_id=execution_id,
            adapter_id="local-tool-registry",
            operation=name,
        )
        started_ns = time.monotonic_ns()
        try:
            result = tool.handler(*safe_args, **safe_kwargs)
        except Exception as handler_error:
            duration_ms = max(0, (time.monotonic_ns() - started_ns) // 1_000_000)
            try:
                authority.record_execution_result(
                    start_sequence=start_sequence,
                    execution_id=execution_id,
                    outcome="timed_out" if isinstance(handler_error, TimeoutError) else "failed",
                    duration_ms=duration_ms,
                    error_type=type(handler_error).__name__,
                )
            except Exception as audit_error:
                raise ToolExecutionAuditError(
                    "tool raised, but its outcome could not be recorded; reconcile before retrying"
                ) from audit_error
            raise
        duration_ms = max(0, (time.monotonic_ns() - started_ns) // 1_000_000)
        try:
            authority.record_execution_result(
                start_sequence=start_sequence,
                execution_id=execution_id,
                outcome="succeeded",
                duration_ms=duration_ms,
            )
        except Exception as audit_error:
            raise ToolExecutionAuditError(
                "tool returned, but its success could not be recorded; reconcile before retrying"
            ) from audit_error
        return result

    def describe(self) -> list[dict[str, Any]]:
        """Return a safe, serializable catalog; handlers are never exposed."""
        return [
            {
                "name": item.name,
                "description": item.description,
                "mutates": item.mutates,
                "capability": item.capability,
                "scope_bound": item.scope_resolver is not None,
            }
            for item in sorted(self._tools.values(), key=lambda item: item.name)
        ]

def _project_resource(target: str | Path, *_args: Any, **_kwargs: Any) -> str:
    """Bind a local project capability to the canonical target directory."""
    root = Path(target).expanduser().resolve()
    return f"project:{root.as_posix()}"


def _project_repair_resource(
    target: str | Path,
    proposals: list[RepairProposal],
    backup_dir: str | Path | None = None,
    *_args: Any,
    **_kwargs: Any,
) -> str:
    """Bind repair authorization to the project and keep backup writes in scope."""
    root = Path(target).expanduser().resolve()
    if backup_dir is not None:
        backup_root = Path(backup_dir).expanduser().resolve()
        try:
            backup_root.relative_to(root)
        except ValueError as exc:
            raise ToolPermissionError(
                "repair backup directory must remain inside the authorized project scope"
            ) from exc
        if backup_root == root:
            raise ToolPermissionError(
                "repair backup directory must be a dedicated directory inside the project"
            )
    return f"project:{root.as_posix()}"


def create_local_registry() -> ToolRegistry:
    """Create the built-in, offline tool set."""
    registry = ToolRegistry()
    registry.register(ActionTool(
        "scan_project",
        "Read and statically analyze supported source and configuration files in a local directory.",
        scan_directory,
        mutates=False,
        capability="project.inspect",
        scope_resolver=_project_resource,
    ))
    registry.register(ActionTool(
        "map_project",
        "Build a read-only AST index of Python modules, imports, classes, functions, and call sites.",
        build_project_map,
        mutates=False,
        capability="project.inspect",
        scope_resolver=_project_resource,
    ))
    registry.register(ActionTool(
        "propose_repairs",
        "Generate supported deterministic repair previews without changing files.",
        propose_repairs,
        mutates=False,
        capability="project.inspect",
        scope_resolver=_project_resource,
    ))
    registry.register(ActionTool(
        "apply_supported_repairs",
        "Apply only built-in deterministic repairs, create backups, rescan, and roll back failures.",
        apply_repairs,
        mutates=True,
        capability="project.repair",
        scope_resolver=_project_repair_resource,
    ))
    return registry

@dataclass(frozen=True, slots=True)
class MissionStep:
    name: str
    status: str
    detail: str
    mutates: bool = False

@dataclass(slots=True)
class MissionResult:
    target: str
    status: str
    steps: list[MissionStep] = field(default_factory=list)
    project_map: ProjectMap | None = None
    initial_scan: ScanResult | None = None
    proposed_repairs: list[RepairProposal] = field(default_factory=list)
    final_scan: ScanResult | None = None
    backups: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def initial_findings(self) -> list[Finding]:
        return list(self.initial_scan.findings) if self.initial_scan else []

    @property
    def final_findings(self) -> list[Finding]:
        return list(self.final_scan.findings) if self.final_scan else []

    @property
    def manual_review_findings(self) -> list[Finding]:
        """Return current findings not covered by a built-in repair proposal."""
        current = self.final_findings if self.final_scan is not None else self.initial_findings
        supported = set()
        if self.status not in {"failed", "incomplete"}:
            supported = {
                (proposal.path, rule_id)
                for proposal in self.proposed_repairs
                for rule_id in proposal.rule_ids
            }
        return [
            finding for finding in current
            if (finding.path, finding.rule_id) not in supported
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission": "local_security_audit",
            "goal": "Audit a local project and prepare or apply supported repairs.",
            "target": self.target,
            "status": self.status,
            "steps": [asdict(step) for step in self.steps],
            "project_map": self.project_map.to_dict() if self.project_map else None,
            "scanned_files": self.initial_scan.scanned_files if self.initial_scan else 0,
            "initial_findings": [item.to_dict() for item in self.initial_findings],
            "manual_review_findings": [item.to_dict() for item in self.manual_review_findings],
            "proposed_repairs": [
                {"path": item.path, "rule_ids": list(item.rule_ids), "diff": item.diff}
                for item in self.proposed_repairs
            ],
            "applied_backups": [str(item) for item in self.backups],
            "final_findings": [item.to_dict() for item in self.final_findings],
            "errors": list(self.errors),
        }

def run_audit_mission(
    target: str | Path,
    *,
    apply_supported_repairs: bool = False,
    backup_dir: str | Path | None = None,
    registry: ToolRegistry | None = None,
    authority: AuthorityKernel | None = None,
    subject: str | None = None,
    approval_token: str | None = None,
) -> MissionResult:
    """Run an audit plan, optionally enforcing the Authority Kernel at each tool call.

    When authority is supplied, every operation is authorized against a resource
    scope derived from its actual target argument. Mutating repairs additionally
    require an exact-scope one-time approval token. Without authority, the
    historical explicit CLI approval workflow remains available for compatibility.
    """
    if authority is not None:
        if not isinstance(subject, str) or not subject.strip():
            raise ValueError("an authenticated subject from the host is required with authority")
    elif subject is not None or approval_token is not None:
        raise ValueError("subject and approval_token require an AuthorityKernel")

    tools = registry or create_local_registry()
    root = Path(target).expanduser().resolve()

    def invoke_tool(name: str, *args: Any, approval: str | None = None, **kwargs: Any) -> Any:
        if authority is None:
            if name == "apply_supported_repairs":
                # Preserve the explicit, legacy mission flag without routing a
                # mutation through ToolRegistry.call(), whose compatibility
                # boolean is intentionally not an authorization mechanism.
                return apply_repairs(*args, **kwargs)
            return tools.call(name, *args, **kwargs)
        return tools.call_authorized(
            name,
            *args,
            authority=authority,
            subject=subject,
            approval_token=approval,
            **kwargs,
        )
    result = MissionResult(target=str(root), status="running")
    result.steps.append(MissionStep(
        "map_project", "running",
        "Build a structural index of Python files without importing or executing source.",
    ))
    try:
        result.project_map = invoke_tool("map_project", root)
        result.steps[-1] = MissionStep(
            "map_project",
            "incomplete" if result.project_map.warnings else "completed",
            (
                f"Indexed {result.project_map.summary['modules']} Python module(s), "
                f"{result.project_map.summary['classes']} class(es), "
                f"{result.project_map.summary['functions']} function(s), "
                f"and {result.project_map.summary['calls']} call site(s)."
            ),
        )
    except (OSError, ValueError, RuntimeError) as exc:
        result.errors.append(str(exc))
        result.steps[-1] = MissionStep("map_project", "failed", "The structural project map could not be completed.")
        result.status = "failed"
        return result

    result.steps.append(MissionStep(
        "scan_project", "running", "Inspect supported files without executing project code."
    ))
    try:
        initial = invoke_tool("scan_project", root)
        result.initial_scan = initial
        result.steps[-1] = MissionStep(
            "scan_project",
            "incomplete" if initial.errors else "completed",
            f"Scanned {initial.scanned_files} file(s); found {len(initial.findings)} issue(s).",
        )
    except (OSError, ValueError, RuntimeError) as exc:
        result.errors.append(str(exc))
        result.steps[-1] = MissionStep("scan_project", "failed", "The local scan could not be completed.")
        result.status = "failed"
        return result

    if result.project_map.warnings or initial.errors:
        for warning in [*result.project_map.warnings, *initial.errors]:
            if warning not in result.errors:
                result.errors.append(warning)
        result.steps.append(MissionStep(
            "propose_repairs", "skipped",
            "Repair planning is stopped because structural mapping or security scanning was incomplete.",
        ))
        result.status = "incomplete"
        return result

    result.steps.append(MissionStep(
        "propose_repairs", "running",
        "Prepare only built-in deterministic repairs; do not change project files.",
    ))
    try:
        result.proposed_repairs = invoke_tool("propose_repairs", root)
        result.steps[-1] = MissionStep(
            "propose_repairs", "completed",
            f"Prepared {len(result.proposed_repairs)} supported repair proposal(s).",
        )
    except (OSError, ValueError, RuntimeError) as exc:
        result.errors.append(str(exc))
        result.steps[-1] = MissionStep("propose_repairs", "failed", "Repair preview could not be prepared.")
        result.status = "failed"
        return result

    if not result.proposed_repairs:
        result.final_scan = initial
        result.status = "completed_with_findings" if initial.findings else "completed"
        return result

    if not apply_supported_repairs:
        result.steps.append(MissionStep(
            "apply_supported_repairs", "pending_approval",
            "Review the proposed changes, then explicitly rerun with --apply-supported-repairs.",
            mutates=True,
        ))
        result.final_scan = initial
        result.status = "approval_required"
        return result

    result.steps.append(MissionStep(
        "apply_supported_repairs", "running",
        "Apply built-in changes after revalidating file contents and saving backups.",
        mutates=True,
    ))
    try:
        result.backups = invoke_tool(
            "apply_supported_repairs",
            root,
            result.proposed_repairs,
            backup_dir,
            approval=approval_token,
        )
        result.steps[-1] = MissionStep(
            "apply_supported_repairs", "completed",
            f"Applied and internally verified {len(result.backups)} file change(s).",
            mutates=True,
        )
    except ToolApprovalRequired as exc:
        result.errors.append(str(exc))
        result.steps[-1] = MissionStep(
            "apply_supported_repairs", "pending_approval",
            "The project repair grant is present, but a fresh one-time approval is required; no files were changed.",
            mutates=True,
        )
        result.final_scan = initial
        result.status = "approval_required"
        return result
    except (OSError, ValueError, RuntimeError) as exc:
        result.errors.append(str(exc))
        result.steps[-1] = MissionStep(
            "apply_supported_repairs", "failed",
            "The repair operation failed or was denied; no unsupported operation is attempted.",
            mutates=True,
        )
        try:
            result.final_scan = invoke_tool("scan_project", root)
        except (OSError, ValueError, RuntimeError) as scan_exc:
            result.errors.append(f"Post-failure scan could not run: {scan_exc}")
        result.status = "failed"
        return result

    result.steps.append(MissionStep(
        "verify_changes", "running",
        "Run a fresh scan after the repair operation.",
    ))
    try:
        result.final_scan = invoke_tool("scan_project", root)
        if result.final_scan.errors:
            result.errors.extend(result.final_scan.errors)
            result.steps[-1] = MissionStep(
                "verify_changes", "incomplete",
                "The post-repair scan returned warnings and cannot be treated as complete.",
            )
            result.status = "incomplete"
        else:
            result.steps[-1] = MissionStep(
                "verify_changes", "completed",
                f"Verified the project; {len(result.final_scan.findings)} finding(s) remain for review.",
            )
            result.status = "completed_with_findings" if result.final_scan.findings else "completed"
    except (OSError, ValueError, RuntimeError) as exc:
        result.errors.append(str(exc))
        result.steps[-1] = MissionStep("verify_changes", "failed", "The post-repair scan could not be completed.")
        result.status = "failed"
    return result

"""Permission-gated local tool registry and deterministic audit mission runner.

This is a workflow/execution foundation, not a general language model. Tools are
explicitly registered, local-only, and mutating actions require caller approval.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from .models import Finding, ScanResult
from .engine import run_repair_trial
from .project_map import ProjectMap, build_project_map
from .repairs import RepairProposal, apply_repairs, propose_repairs
from .scanner import scan_directory

TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")

class ToolPermissionError(PermissionError):
    """Raised when a mutating tool is invoked without explicit approval."""

@dataclass(frozen=True, slots=True)
class ActionTool:
    name: str
    description: str
    handler: Callable[..., Any]
    mutates: bool = False

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
        if tool.name in self._tools:
            raise ValueError(f"tool is already registered: {tool.name}")
        self._tools[tool.name] = tool

    def call(self, name: str, *args: Any, approve_mutation: bool = False, **kwargs: Any) -> Any:
        try:
            tool = self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown local tool: {name}") from exc
        if tool.mutates and not approve_mutation:
            raise ToolPermissionError(
                f"tool '{name}' changes local project data; explicit approval is required"
            )
        return tool.handler(*args, **kwargs)

    def describe(self) -> list[dict[str, Any]]:
        """Return a safe, serializable catalog; handlers are never exposed."""
        return [
            {"name": item.name, "description": item.description, "mutates": item.mutates}
            for item in sorted(self._tools.values(), key=lambda item: item.name)
        ]

def create_local_registry() -> ToolRegistry:
    """Create the built-in, offline tool set."""
    registry = ToolRegistry()
    registry.register(ActionTool(
        "scan_project",
        "Read and statically analyze supported source and configuration files in a local directory.",
        scan_directory,
        mutates=False,
    ))
    registry.register(ActionTool(
        "map_project",
        "Build a read-only AST index of Python modules, imports, classes, functions, and call sites.",
        build_project_map,
        mutates=False,
    ))
    registry.register(ActionTool(
        "propose_repairs",
        "Generate supported deterministic repair previews without changing files.",
        propose_repairs,
        mutates=False,
    ))
    registry.register(ActionTool(
        "trial_repairs",
        "Evaluate built-in repair proposals in a disposable workspace without changing project files.",
        run_repair_trial,
        mutates=False,
    ))
    registry.register(ActionTool(
        "apply_supported_repairs",
        "Apply only built-in deterministic repairs, create backups, rescan, and roll back failures.",
        apply_repairs,
        mutates=True,
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
) -> MissionResult:
    """Run an audit plan. Mutating tools are unreachable unless explicitly approved."""
    tools = registry or create_local_registry()
    root = Path(target).expanduser().resolve()
    result = MissionResult(target=str(root), status="running")
    result.steps.append(MissionStep(
        "map_project", "running",
        "Build a structural index of Python files without importing or executing source.",
    ))
    try:
        result.project_map = tools.call("map_project", root)
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
        initial = tools.call("scan_project", root)
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
        result.proposed_repairs = tools.call("propose_repairs", root)
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
        result.backups = tools.call(
            "apply_supported_repairs",
            root,
            result.proposed_repairs,
            backup_dir,
            approve_mutation=True,
        )
        result.steps[-1] = MissionStep(
            "apply_supported_repairs", "completed",
            f"Applied and internally verified {len(result.backups)} file change(s).",
            mutates=True,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        result.errors.append(str(exc))
        result.steps[-1] = MissionStep(
            "apply_supported_repairs", "failed",
            "The repair operation failed; built-in repair logic attempts to restore backed-up originals.",
            mutates=True,
        )
        try:
            result.final_scan = tools.call("scan_project", root)
        except (OSError, ValueError, RuntimeError) as scan_exc:
            result.errors.append(f"Post-failure scan could not run: {scan_exc}")
        result.status = "failed"
        return result

    result.steps.append(MissionStep(
        "verify_changes", "running",
        "Run a fresh scan after the repair operation.",
    ))
    try:
        result.final_scan = tools.call("scan_project", root)
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

"""Command-line interface for offline scanning, baselines, and repair previews."""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .authority import AuthorityKernel, DEFAULT_CAPABILITIES
from .autonomy import create_local_registry, run_audit_mission
from .baselines import compare_with_baseline, create_baseline, load_baseline
from .models import SEVERITY_ORDER
from .project_map import build_project_map
from .reporters import to_json, to_markdown, to_sarif, to_text
from .repairs import apply_repairs, propose_repairs
from .rules import RULES
from .scanner import scan_directory
from .webserver import serve

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegisforge", description="Offline, evidence-based source/configuration security analysis.")
    parser.add_argument("--version", action="version", version=f"AegisForge {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    project_map = commands.add_parser("map", help="Index Python modules, symbols, imports and call sites without executing code")
    project_map.add_argument("target", help="Local project directory")
    project_map.add_argument("--format", choices=("text", "json"), default="text")
    project_map.add_argument("--output", help="Write the index to a file instead of stdout")

    scan = commands.add_parser("scan", help="Scan a local project directory")
    scan.add_argument("target", help="Directory you own or are authorized to assess")
    scan.add_argument("--format", choices=("text", "markdown", "json", "sarif"), default="text")
    scan.add_argument("--output", help="Write the report to this file instead of stdout")
    scan.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "info", "none"), default="high")

    repair = commands.add_parser("repair", help="Preview conservative local repairs; use --apply to write them")
    repair.add_argument("target", help="Project directory you own or are authorized to modify")
    repair.add_argument("--apply", action="store_true", help="Apply supported changes after creating backups")
    repair.add_argument("--backup-dir", help="Optional directory for original-file backups")

    server = commands.add_parser("serve", help="Open the local browser security workbench")
    server.add_argument("--host", choices=("127.0.0.1", "::1"), default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)

    commands.add_parser("rules", help="List checks included in this release")

    tools = commands.add_parser("tools", help="List the explicitly registered local tools")
    tools.add_argument("--format", choices=("text", "json"), default="text")

    mission = commands.add_parser("mission", help="Run a deterministic local engineering mission")
    mission_actions = mission.add_subparsers(dest="mission_action", required=True)
    audit = mission_actions.add_parser("audit", help="Scan a project and prepare supported repair steps")
    audit.add_argument("target", help="Local project directory you own or are authorized to modify")
    audit.add_argument("--apply-supported-repairs", action="store_true", help="Explicitly approve built-in local file changes")
    audit.add_argument("--backup-dir", help="Optional directory for repair backups")
    audit.add_argument("--format", choices=("text", "json"), default="text")

    authority = commands.add_parser("authority", help="Evaluate a scoped capability policy and record the decision")
    authority_actions = authority.add_subparsers(dest="authority_action", required=True)
    check = authority_actions.add_parser("check", help="Check one exact-scope capability (never runs the requested action)")
    check.add_argument("--policy", required=True, help="Version 1 JSON policy file")
    check.add_argument("--audit-log", required=True, help="Append-only JSONL decision log path")
    check.add_argument("--subject", required=True, help="Caller identity asserted by the invoking host")
    check.add_argument("--capability", required=True, help="Named capability, e.g. project.inspect")
    check.add_argument("--resource", required=True, help="Exact resource identifier; no wildcard matching")
    check.add_argument("--format", choices=("text", "json"), default="text")

    inspect = authority_actions.add_parser("audit", help="Verify and inspect a saved authority audit ledger")
    inspect.add_argument("--audit-log", required=True, help="Existing append-only JSONL audit log")
    inspect.add_argument("--format", choices=("text", "json"), default="text")

    baseline = commands.add_parser("baseline", help="Create or compare a local finding baseline")
    actions = baseline.add_subparsers(dest="baseline_action", required=True)
    create = actions.add_parser("create", help="Record the current complete scan as a baseline")
    create.add_argument("target")
    create.add_argument("--output", help="Baseline JSON path (default: TARGET/.aegisforge/baseline.json)")
    compare = actions.add_parser("compare", help="Compare current findings with a saved baseline")
    compare.add_argument("target")
    compare.add_argument("--input", dest="baseline_path", required=True)
    compare.add_argument("--format", choices=("text", "json"), default="text")

    return parser

def _write_report(report: str, destination: str | None) -> int:
    if not destination:
        sys.stdout.write(report)
        return 0
    path = Path(destination).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report, encoding="utf-8")
    except OSError as exc:
        print(f"AegisForge: cannot write report: {exc}", file=sys.stderr)
        return 2
    print(f"Report written to {path}")
    return 0

def _run_scan(args: argparse.Namespace) -> int:
    result = scan_directory(args.target)
    renderers = {"text": to_text, "markdown": to_markdown, "json": to_json, "sarif": to_sarif}
    status = _write_report(renderers[args.format](result), args.output)
    if status:
        return status
    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[item.severity] <= threshold for item in result.findings):
            return 1
    if result.errors:
        return 2
    return 0

def _run_map(args: argparse.Namespace) -> int:
    project_map = build_project_map(args.target)
    if args.format == "json":
        report = json.dumps(project_map.to_dict(), indent=2, ensure_ascii=False) + "\n"
    else:
        lines = [
            f"AegisForge project map: {project_map.project}",
            f"Python files indexed: {project_map.scanned_files} | skipped: {project_map.skipped_files}",
            "Summary: " + ", ".join(f"{key}={value}" for key, value in project_map.summary.items()),
        ]
        for module in project_map.modules:
            lines.extend(["", f"MODULE {module.module} ({module.path})"])
            for item in module.imports:
                imported = f" import {item.imported_name}" if item.imported_name else ""
                alias = f" as {item.alias}" if item.alias else ""
                relative = "." * item.relative_level
                lines.append(f"  IMPORT {relative}{item.module}{imported}{alias} [line {item.line}]")
            for symbol in module.symbols:
                params = f" parameters={symbol.parameters}" if symbol.kind != "class" else ""
                lines.append(f"  {symbol.kind.upper()} {symbol.qualified_name} [lines {symbol.line}-{symbol.end_line}]{params}")
            for call in module.calls:
                lines.append(f"  CALL {call.caller} -> {call.callee} [line {call.line}]")
        if project_map.warnings:
            lines.extend(["", "WARNINGS:"] + [f"  {warning}" for warning in project_map.warnings])
        report = "\n".join(lines) + "\n"
    status = _write_report(report, args.output)
    if status:
        return status
    return 2 if project_map.warnings else 0

def _run_repair(args: argparse.Namespace) -> int:
    proposals = propose_repairs(args.target)
    if not proposals:
        print("No supported conservative repairs were found.")
        return 0
    print(f"{'Applying' if args.apply else 'Preview only'}: {len(proposals)} proposed file change(s).")
    for proposal in proposals:
        print(f"\n{proposal.path} [{', '.join(proposal.rule_ids)}]")
        sys.stdout.write(proposal.diff)
    if not args.apply:
        print("\nNo files were changed. Review the diff, then rerun with --apply to write changes.")
        return 0
    backups = apply_repairs(args.target, proposals, args.backup_dir)
    print(f"\nApplied and verified {len(proposals)} file change(s). Backups: {len(backups)}")
    return 0

def _run_tools(args: argparse.Namespace) -> int:
    catalog = create_local_registry().describe()
    if args.format == "json":
        sys.stdout.write(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n")
    else:
        print("AegisForge local tool catalog")
        for item in catalog:
            permission = "MUTATES — approval required" if item["mutates"] else "READ ONLY"
            print(f"{item['name']:28} {permission}\n  {item['description']}")
    return 0

def _run_mission(args: argparse.Namespace) -> int:
    result = run_audit_mission(
        args.target,
        apply_supported_repairs=args.apply_supported_repairs,
        backup_dir=args.backup_dir,
    )
    if args.format == "json":
        sys.stdout.write(json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n")
    else:
        print("AegisForge mission: local security audit")
        print(f"Target: {result.target}")
        print(f"Status: {result.status}")
        if result.project_map is not None:
            mapped = result.project_map.summary
            print(
                "Project map: "
                f"{mapped['modules']} modules, {mapped['classes']} classes, "
                f"{mapped['functions']} functions, {mapped['calls']} call sites"
            )
        for step in result.steps:
            mutation = " [MUTATING]" if step.mutates else ""
            print(f"  [{step.status.upper()}] {step.name}{mutation} — {step.detail}")
        print(f"Initial findings: {len(result.initial_findings)}")
        for finding in result.initial_findings:
            print(f"  [{finding.severity.upper()}] {finding.rule_id} {finding.path}:{finding.line} — {finding.title}")
        if result.proposed_repairs:
            print(f"\nSupported repair proposals: {len(result.proposed_repairs)}")
            for proposal in result.proposed_repairs:
                print(f"\n{proposal.path} [{', '.join(proposal.rule_ids)}]")
                sys.stdout.write(proposal.diff)
        if result.backups:
            print(f"\nBackups created: {len(result.backups)}")
        if result.manual_review_findings:
            print(f"\nManual review required: {len(result.manual_review_findings)} finding(s)")
            for finding in result.manual_review_findings:
                print(f"  [{finding.severity.upper()}] {finding.rule_id} {finding.path}:{finding.line} — {finding.title}")
        if result.final_scan is not None:
            print(f"Final findings: {len(result.final_findings)}")
        for error in result.errors:
            print(f"ERROR: {error}")
        if result.status == "approval_required":
            print("\nNo files were changed. Review proposals, then rerun with --apply-supported-repairs to authorize them.")
    return 2 if result.status in {"failed", "incomplete"} else 0

def _run_authority_check(args: argparse.Namespace) -> int:
    kernel = AuthorityKernel.from_policy_file(
        DEFAULT_CAPABILITIES,
        args.policy,
        audit_path=args.audit_log,
    )
    decision = kernel.authorize(
        subject=args.subject,
        capability=args.capability,
        resource=args.resource,
    )
    if args.format == "json":
        sys.stdout.write(json.dumps(decision.to_dict(), indent=2, ensure_ascii=False) + "\n")
    else:
        status = "ALLOW" if decision.allowed else "DENY"
        print(f"Authority decision: {status}")
        print(f"Subject: {decision.subject}")
        print(f"Capability: {decision.capability}")
        print(f"Exact resource: {decision.resource}")
        print(f"Reason: {decision.reason}")
        print(f"Audit sequence: {decision.audit_sequence}")
        print("No operation was executed by this check.")
    return 0 if decision.allowed else 1


def _run_authority_audit(args: argparse.Namespace) -> int:
    path = Path(args.audit_log).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"audit log does not exist or is not a regular file: {path}")

    # Construction verifies the complete hash chain before any data is displayed.
    # This command intentionally performs no writes and never retries an execution.
    kernel = AuthorityKernel(DEFAULT_CAPABILITIES, audit_path=path)
    entries = kernel.audit_entries()
    pending = kernel.pending_executions()
    if args.format == "json":
        payload = {
            "tool": "AegisForge",
            "verified": True,
            "entry_count": len(entries),
            "entries": entries,
            "pending_count": len(pending),
            "pending_executions": pending,
        }
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\\n")
        return 0

    print("Authority audit ledger: VERIFIED")
    print(f"Entries: {len(entries)}")
    for entry in entries:
        event = entry["event"]
        event_type = event.get("type", "unknown")
        prefix = f"[{entry['sequence']:04d}] {entry['timestamp']} {event_type}"
        if event_type == "authorization_decision":
            verdict = "ALLOW" if event.get("allowed") else "DENY"
            detail = (
                f"{verdict} {event.get('subject')} {event.get('capability')} "
                f"@ {event.get('resource')} ({event.get('reason')})"
            )
        elif event_type == "execution_started":
            detail = (
                f"{event.get('adapter_id')}.{event.get('operation')} "
                f"execution={event.get('execution_id')} "
                f"@ {event.get('resource')}"
            )
        elif event_type == "execution_result":
            detail = (
                f"{event.get('outcome')} execution={event.get('execution_id')} "
                f"duration_ms={event.get('duration_ms')}"
            )
        elif event_type == "approval_issued":
            detail = (
                f"{event.get('subject')} {event.get('capability')} "
                f"@ {event.get('resource')} approver={event.get('approver')}"
            )
        else:
            detail = "unrecognized event"
        print(f"{prefix} — {detail}")

    print(f"Unresolved executions: {len(pending)}")
    for item in pending:
        print(
            f"  OUTCOME UNKNOWN {item['adapter_id']}.{item['operation']} "
            f"execution={item['execution_id']} @ {item['resource']}"
        )
    if not pending:
        print("  None")
    print("This command is read-only. Reconcile unknown outcomes before retrying.")
    return 0


def _run_baseline_create(args: argparse.Namespace) -> int:
    result = scan_directory(args.target)
    destination = args.output or str(Path(result.root) / ".aegisforge" / "baseline.json")
    payload = create_baseline(result, destination)
    print(f"Baseline created: {destination}")
    print(f"Recorded {len(payload['findings'])} finding(s) across {payload['scanned_files']} scanned file(s).")
    return 0

def _run_baseline_compare(args: argparse.Namespace) -> int:
    baseline = load_baseline(args.baseline_path)
    result = scan_directory(args.target)
    comparison = compare_with_baseline(result, baseline)
    if args.format == "json":
        payload = {
            "tool": "AegisForge",
            "baseline": str(Path(args.baseline_path).expanduser()),
            "new": [item.to_dict() for item in comparison["new"]],
            "known": [item.to_dict() for item in comparison["known"]],
            "resolved": [item.to_dict() for item in comparison["resolved"]],
            "scan_errors": result.errors,
        }
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    else:
        print(f"Baseline comparison: {args.target}")
        print(f"New: {len(comparison['new'])} | Known: {len(comparison['known'])} | Resolved: {len(comparison['resolved'])}")
        for label in ("new", "known", "resolved"):
            print(f"\n{label.title()} findings:")
            for item in comparison[label]:
                print(f"  [{item.severity.upper()}] {item.rule_id} {item.path}:{item.line} — {item.title}")
        for error in result.errors:
            print(f"WARNING: {error}")
    return 2 if result.errors else 0

def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "rules":
            for rule in RULES:
                print(f"{rule.rule_id:12} {rule.severity.upper():8} {rule.title}\n             {rule.description}")
            return 0
        if args.command == "tools":
            return _run_tools(args)
        if args.command == "mission" and args.mission_action == "audit":
            return _run_mission(args)
        if args.command == "authority" and args.authority_action == "check":
            return _run_authority_check(args)
        if args.command == "authority" and args.authority_action == "audit":
            return _run_authority_audit(args)
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "map":
            return _run_map(args)
        if args.command == "serve":
            serve(args.host, args.port)
            return 0
        if args.command == "repair":
            return _run_repair(args)
        if args.command == "baseline" and args.baseline_action == "create":
            return _run_baseline_create(args)
        if args.command == "baseline" and args.baseline_action == "compare":
            return _run_baseline_compare(args)
        print("AegisForge: unsupported command", file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"AegisForge: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())

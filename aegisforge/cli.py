"""Command-line interface for offline scanning, baselines, and repair previews."""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .autonomy import create_local_registry, run_audit_mission
from .engine import load_plan_file, run_repair_trial, run_trial
from .baselines import compare_with_baseline, create_baseline, load_baseline
from .models import SEVERITY_ORDER
from .reporters import to_json, to_markdown, to_sarif, to_text
from .repairs import apply_repairs, propose_repairs
from .rules import RULES
from .scanner import scan_directory
from .webserver import serve

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegisforge", description="Offline, evidence-based source/configuration security analysis.")
    parser.add_argument("--version", action="version", version=f"AegisForge {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

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

    trial = mission_actions.add_parser("trial", help="Evaluate proposed edits in a disposable workspace without changing project files")
    trial.add_argument("target", help="Local project directory you own or are authorized to modify")
    trial.add_argument("--plan", help="Optional hash-checked JSON replacement plan; omit to test built-in repair proposals")
    trial.add_argument("--format", choices=("text", "json"), default="text")
    trial.add_argument("--output", help="Write the trial report to this file instead of stdout")

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
        if result.final_scan is not None:
            print(f"Final findings: {len(result.final_findings)}")
        for error in result.errors:
            print(f"ERROR: {error}")
        if result.status == "approval_required":
            print("\nNo files were changed. Review proposals, then rerun with --apply-supported-repairs to authorize them.")
    return 2 if result.status in {"failed", "incomplete"} else 0

def _run_mission_trial(args: argparse.Namespace) -> int:
    if args.plan:
        plan = load_plan_file(args.plan)
        result = run_trial(args.target, plan)
    else:
        result = run_repair_trial(args.target)

    if args.format == "json":
        report = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    else:
        lines = [
            "AegisForge mission trial",
            f"Target: {result['target']}",
            f"Decision: {result['decision']}",
            f"Reason: {result.get('reason', '')}",
            f"Changed files: {', '.join(result.get('changed_files', [])) or 'none'}",
        ]
        for item in result.get("resolved_findings", []):
            lines.append(f"RESOLVED {item['rule_id']} {item['path']}:{item['line']}")
        for item in result.get("introduced_findings", []):
            lines.append(f"INTRODUCED [{item['severity'].upper()}] {item['rule_id']} {item['path']}:{item['line']}")
        lines.append("Original project modified: no")
        lines.append("Candidate project code executed: no")
        report = "\n".join(lines) + "\n"

    status = _write_report(report, args.output)
    if status:
        return status
    return 1 if result["decision"] == "rejected" else 0

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
        if args.command == "mission" and args.mission_action == "trial":
            return _run_mission_trial(args)
        if args.command == "scan":
            return _run_scan(args)
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

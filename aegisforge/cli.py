"""Command-line interface for offline scanning, baselines, repair previews, and trials."""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .baselines import compare_with_baseline, create_baseline, load_baseline
from .engine import load_plan_file, run_trial
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

    engine = commands.add_parser("engine", help="Run controlled engineering trials in disposable workspaces")
    engine_actions = engine.add_subparsers(dest="engine_action", required=True)
    trial = engine_actions.add_parser("trial", help="Test hash-checked file replacements without modifying the source project")
    trial.add_argument("target", help="Local project directory you own or are authorized to modify")
    trial.add_argument("--plan", required=True, help="UTF-8 JSON file containing hash-checked replacement operations")
    trial.add_argument("--output", help="Write the JSON trial report to this file instead of stdout")

    server = commands.add_parser("serve", help="Open the local browser security workbench")
    server.add_argument("--host", choices=("127.0.0.1", "::1"), default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)

    commands.add_parser("rules", help="List checks included in this release")

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


def _run_engine_trial(args: argparse.Namespace) -> int:
    plan = load_plan_file(args.plan)
    report = run_trial(args.target, plan)
    status = _write_report(json.dumps(report, indent=2, ensure_ascii=False) + "\n", args.output)
    if status:
        return status
    return 1 if report["decision"] == "rejected" else 0


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
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "serve":
            serve(args.host, args.port)
            return 0
        if args.command == "repair":
            return _run_repair(args)
        if args.command == "engine" and args.engine_action == "trial":
            return _run_engine_trial(args)
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

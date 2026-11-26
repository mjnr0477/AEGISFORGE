"""Command-line interface for offline scanning."""
import argparse
import sys
from pathlib import Path
from . import __version__
from .models import SEVERITY_ORDER
from .reporters import to_json, to_markdown, to_sarif, to_text
from .rules import RULES
from .scanner import scan_directory

def build_parser():
    parser = argparse.ArgumentParser(prog="aegisforge", description="Offline source/configuration security analysis.")
    parser.add_argument("--version", action="version", version=f"AegisForge {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a local project you own or are authorized to assess")
    scan.add_argument("target")
    scan.add_argument("--format", choices=("text","markdown","json","sarif"), default="text")
    scan.add_argument("--output")
    scan.add_argument("--fail-on", choices=("critical","high","medium","low","info","none"), default="high")
    sub.add_parser("rules", help="List included security checks")
    return parser

def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        for rule in RULES:
            print(f"{rule.rule_id:12} {rule.severity.upper():8} {rule.title}\n             {rule.description}")
        return 0
    try:
        result = scan_directory(args.target)
    except (OSError, ValueError) as exc:
        print(f"AegisForge: {exc}", file=sys.stderr)
        return 2
    render = {"text":to_text,"markdown":to_markdown,"json":to_json,"sarif":to_sarif}[args.format]
    report = render(result)
    if args.output:
        try:
            Path(args.output).expanduser().write_text(report, encoding="utf-8")
        except OSError as exc:
            print(f"AegisForge: cannot write report: {exc}", file=sys.stderr)
            return 2
        print(f"Report written to {Path(args.output).expanduser()}")
    else:
        sys.stdout.write(report)
    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= threshold for f in result.findings):
            return 1
    return 0

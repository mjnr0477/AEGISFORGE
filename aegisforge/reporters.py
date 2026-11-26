"""Human-readable and machine-readable report renderers."""
import json
from . import __version__
from .models import ScanResult
from .rules import RULE_MAP

def to_text(result: ScanResult) -> str:
    counts = result.summary()
    lines = [f"AegisForge scan: {result.root}", f"Files scanned: {result.scanned_files} | skipped: {result.skipped_files}", f"Findings: {len(result.findings)}", "Severity: " + ", ".join(f"{k}={v}" for k, v in counts.items())]
    for item in result.findings:
        lines.extend(["", f"[{item.severity.upper()}] {item.rule_id} — {item.title}", f"  {item.path}:{item.line}:{item.column}", f"  Evidence: {item.evidence}", f"  {item.message}", f"  Fix: {item.remediation}"])
    lines.extend(f"WARNING: {err}" for err in result.errors)
    if not result.findings:
        lines.append("No findings matched the current rules. This is not a security certification.")
    return "\n".join(lines) + "\n"

def to_markdown(result: ScanResult) -> str:
    lines = ["# AegisForge security report", "", f"- Target: {result.root}", f"- Files scanned: {result.scanned_files}", f"- Files skipped: {result.skipped_files}", f"- Findings: {len(result.findings)}", "", "> Static-analysis signals require human validation. A clean report is not proof of security.", ""]
    for item in result.findings:
        lines.extend([f"## [{item.severity.upper()}] {item.title}", "", f"- Rule: {item.rule_id}", f"- Location: {item.path}:{item.line}:{item.column}", f"- Evidence: {item.evidence}", "", item.message, "", f"Suggested remediation: {item.remediation}", ""])
    if result.errors:
        lines.extend(["## Warnings", ""] + [f"- {error}" for error in result.errors])
    return "\n".join(lines)

def to_json(result: ScanResult) -> str:
    payload = {"tool":{"name":"AegisForge","version":__version__},"root":result.root,"scanned_files":result.scanned_files,"skipped_files":result.skipped_files,"summary":result.summary(),"findings":[f.to_dict() for f in result.findings],"errors":result.errors}
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

def to_sarif(result: ScanResult) -> str:
    rules = [{"id":r.rule_id,"name":r.title,"shortDescription":{"text":r.title},"fullDescription":{"text":r.description},"help":{"text":r.remediation}} for r in RULE_MAP.values()]
    results = [{"ruleId":f.rule_id,"level":{"critical":"error","high":"error","medium":"warning","low":"note","info":"note"}.get(f.severity,"warning"),"message":{"text":f.message},"locations":[{"physicalLocation":{"artifactLocation":{"uri":f.path},"region":{"startLine":f.line,"startColumn":f.column,"snippet":{"text":f.evidence}}}}]} for f in result.findings]
    return json.dumps({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"AegisForge","version":__version__,"rules":rules}},"results":results}]}, indent=2) + "\n"

"""Local, integrity-checked finding baselines for regression tracking."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from . import __version__
from .models import Finding, ScanResult, SEVERITY_ORDER

BASELINE_SCHEMA_VERSION = 1
MAX_BASELINE_BYTES = 20 * 1024 * 1024

def finding_fingerprint(finding: Finding) -> str:
    """Create a deterministic identity for one exact finding location/evidence."""
    identity = {
        "rule_id": finding.rule_id,
        "path": finding.path,
        "line": finding.line,
        "column": finding.column,
        "evidence": finding.evidence,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def create_baseline(result: ScanResult, destination: str | Path) -> dict[str, Any]:
    """Write a complete scan as a baseline using an atomic local file replace."""
    if result.errors:
        raise ValueError("cannot create a baseline from an incomplete scan; resolve scan warnings first")
    payload: dict[str, Any] = {
        "tool": "AegisForge",
        "tool_version": __version__,
        "schema_version": BASELINE_SCHEMA_VERSION,
        "project": Path(result.root).name,
        "scanned_files": result.scanned_files,
        "findings": [
            {"fingerprint": finding_fingerprint(item), **item.to_dict()}
            for item in sorted(result.findings, key=lambda value: (value.path, value.line, value.column, value.rule_id))
        ],
    }
    serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if len(serialized.encode("utf-8")) > MAX_BASELINE_BYTES:
        raise ValueError(f"baseline exceeds the {MAX_BASELINE_BYTES}-byte write limit")
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as handle:
            temporary_name = handle.name
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return payload

def _finding_from_entry(entry: dict[str, Any]) -> Finding:
    expected = {
        "fingerprint", "rule_id", "severity", "title", "message", "path", "line",
        "column", "evidence", "remediation", "confidence", "cwe",
    }
    if set(entry) != expected:
        raise ValueError("invalid baseline finding fields")
    fingerprint = entry["fingerprint"]
    if not isinstance(fingerprint, str) or len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint.lower()):
        raise ValueError("invalid baseline finding fingerprint")
    finding_data = {key: value for key, value in entry.items() if key != "fingerprint"}
    if not isinstance(finding_data["path"], str) or not finding_data["path"] or "\\" in finding_data["path"] or "\x00" in finding_data["path"]:
        raise ValueError("invalid baseline finding path")
    relative = PurePosixPath(finding_data["path"])
    if not relative.parts or relative.as_posix() != finding_data["path"] or relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("baseline finding path must be a safe relative path")
    if type(finding_data["line"]) is not int or finding_data["line"] < 1:
        raise ValueError("invalid baseline finding line")
    if type(finding_data["column"]) is not int or finding_data["column"] < 1:
        raise ValueError("invalid baseline finding column")
    if not isinstance(finding_data["severity"], str) or finding_data["severity"] not in SEVERITY_ORDER:
        raise ValueError("invalid baseline finding severity")
    for field in ("rule_id", "title", "message", "evidence", "remediation", "confidence"):
        if not isinstance(finding_data[field], str):
            raise ValueError(f"invalid baseline finding {field}")
    if len(finding_data["evidence"]) > 180:
        raise ValueError("baseline finding evidence exceeds the supported limit")
    if finding_data["cwe"] is not None and not isinstance(finding_data["cwe"], str):
        raise ValueError("invalid baseline finding CWE")
    finding = Finding(**finding_data)
    if finding_fingerprint(finding) != fingerprint:
        raise ValueError("baseline finding fingerprint does not match its contents")
    return finding

def load_baseline(source: str | Path) -> dict[str, Any]:
    """Load and validate a baseline, including every finding fingerprint."""
    path = Path(source).expanduser()
    try:
        if path.stat().st_size > MAX_BASELINE_BYTES:
            raise ValueError(f"baseline exceeds the {MAX_BASELINE_BYTES}-byte read limit")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read baseline: {exc}") from exc
    if not isinstance(payload, dict) or type(payload.get("schema_version")) is not int or payload.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError(f"unsupported baseline schema; expected version {BASELINE_SCHEMA_VERSION}")
    if payload.get("tool") != "AegisForge" or not isinstance(payload.get("findings"), list):
        raise ValueError("invalid baseline structure")
    if not isinstance(payload.get("project"), str) or type(payload.get("scanned_files")) is not int or payload["scanned_files"] < 0:
        raise ValueError("invalid baseline metadata")
    seen: set[str] = set()
    for entry in payload["findings"]:
        if not isinstance(entry, dict):
            raise ValueError("invalid baseline finding entry")
        _finding_from_entry(entry)
        fingerprint = entry["fingerprint"]
        if fingerprint in seen:
            raise ValueError("duplicate baseline finding fingerprint")
        seen.add(fingerprint)
    return payload

def compare_with_baseline(result: ScanResult, baseline: dict[str, Any]) -> dict[str, list[Finding]]:
    """Classify current findings as new/known and baseline-only findings as resolved."""
    baseline_by_fingerprint = {entry["fingerprint"]: _finding_from_entry(entry) for entry in baseline["findings"]}
    current_by_fingerprint = {finding_fingerprint(item): item for item in result.findings}
    new = [item for key, item in current_by_fingerprint.items() if key not in baseline_by_fingerprint]
    known = [item for key, item in current_by_fingerprint.items() if key in baseline_by_fingerprint]
    resolved = [item for key, item in baseline_by_fingerprint.items() if key not in current_by_fingerprint]
    return {"new": new, "known": known, "resolved": resolved}

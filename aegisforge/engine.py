"""Controlled engineering trials on disposable copies of local projects.

The trial engine never executes candidate project code or shell commands. It applies
hash-checked text replacements in a temporary workspace, then compares static scans.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

from .models import SEVERITY_ORDER
from .scanner import MAX_FILE_BYTES, collect_files, scan_directory

PLAN_SCHEMA_VERSION = 1
MAX_PLAN_BYTES = 2 * 1024 * 1024
MAX_CHANGES = 100
MAX_REPLACEMENT_BYTES = 1_000_000
MAX_TOTAL_REPLACEMENT_BYTES = 10 * 1024 * 1024
_HEX = frozenset("0123456789abcdef")


def _read_regular_bytes(path: Path, max_bytes: int) -> bytes:
    """Read one regular file without following a symlink or trusting stale metadata."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"refusing non-regular file: {path}")
    if before.st_size > max_bytes:
        raise ValueError(f"file exceeds {max_bytes} bytes: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError(f"file changed while opening: {path}")
        if opened.st_size > max_bytes:
            raise ValueError(f"file exceeds {max_bytes} bytes: {path}")
        before_read = (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        after_read = os.fstat(descriptor)
        after_state = (after_read.st_size, after_read.st_mtime_ns, after_read.st_ctime_ns)
        if before_read != after_state:
            raise ValueError(f"file changed while being read: {path}")
        if len(data) > max_bytes:
            raise ValueError(f"file exceeds {max_bytes} bytes: {path}")
        return data
    finally:
        os.close(descriptor)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_plan_file(path: str | Path) -> dict[str, Any]:
    """Load a bounded UTF-8 JSON trial plan, rejecting symlinks and duplicate keys."""
    plan_path = Path(path).expanduser()
    try:
        raw = _read_regular_bytes(plan_path, MAX_PLAN_BYTES)
        text = raw.decode("utf-8")
        plan = json.loads(text, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read trial plan: {exc}") from exc
    return validate_plan(plan)


def _safe_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("change path must be a non-empty relative POSIX path")
    if any(ord(char) < 32 for char in value):
        raise ValueError("change path contains a control character")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or relative.as_posix() != value
        or any(part in {"", ".", ".."} for part in relative.parts)
        or ":" in relative.parts[0]
    ):
        raise ValueError(f"unsafe change path: {value}")
    return value


def validate_plan(plan: Any) -> dict[str, Any]:
    """Validate a declarative replacement plan; no command or script fields are accepted."""
    if not isinstance(plan, dict) or set(plan) != {"schema_version", "changes"}:
        raise ValueError("trial plan must contain only schema_version and changes")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != PLAN_SCHEMA_VERSION:
        raise ValueError(f"unsupported trial plan schema; expected {PLAN_SCHEMA_VERSION}")
    changes = plan["changes"]
    if not isinstance(changes, list) or not changes or len(changes) > MAX_CHANGES:
        raise ValueError(f"trial plan must contain 1 to {MAX_CHANGES} changes")

    validated: list[dict[str, str]] = []
    seen: set[str] = set()
    total_bytes = 0
    for index, entry in enumerate(changes, 1):
        if not isinstance(entry, dict) or set(entry) != {"path", "expected_sha256", "replacement"}:
            raise ValueError(f"change {index} must contain only path, expected_sha256, and replacement")
        relative = _safe_relative_path(entry["path"])
        if relative in seen:
            raise ValueError(f"duplicate change path: {relative}")
        seen.add(relative)

        digest = entry["expected_sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(char.lower() not in _HEX for char in digest):
            raise ValueError(f"change {index} has an invalid expected_sha256")
        replacement = entry["replacement"]
        if not isinstance(replacement, str) or "\x00" in replacement:
            raise ValueError(f"change {index} replacement must be NUL-free text")
        try:
            encoded = replacement.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError(f"change {index} replacement is not valid UTF-8 text") from exc
        if len(encoded) > MAX_REPLACEMENT_BYTES:
            raise ValueError(f"change {index} exceeds the replacement size limit")
        total_bytes += len(encoded)
        if total_bytes > MAX_TOTAL_REPLACEMENT_BYTES:
            raise ValueError("trial plan exceeds the total replacement size limit")
        validated.append({"path": relative, "expected_sha256": digest.lower(), "replacement": replacement})
    return {"schema_version": PLAN_SCHEMA_VERSION, "changes": validated}


def _finding_key(finding: Any) -> tuple[str, str, str, str]:
    # Line/column are excluded so harmless insertions above a finding do not look new.
    return finding.rule_id, finding.severity, finding.path, finding.evidence


def _finding_delta(before: list[Any], after: list[Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    before_counts = Counter(_finding_key(item) for item in before)
    after_counts = Counter(_finding_key(item) for item in after)
    introduced_counts = after_counts - before_counts
    resolved_counts = before_counts - after_counts
    introduced: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []

    for item in after:
        key = _finding_key(item)
        if introduced_counts[key] > 0:
            introduced.append(item.to_dict())
            introduced_counts[key] -= 1
    for item in before:
        key = _finding_key(item)
        if resolved_counts[key] > 0:
            resolved.append(item.to_dict())
            resolved_counts[key] -= 1

    order = lambda item: (SEVERITY_ORDER.get(item["severity"], 99), item["path"], item["line"], item["rule_id"])
    introduced.sort(key=order)
    resolved.sort(key=order)
    return introduced, resolved


def run_trial(target: str | Path, plan: dict[str, Any]) -> dict[str, Any]:
    """Evaluate hash-checked replacements in a temporary copy without changing the source."""
    validated = validate_plan(plan)
    requested_root = Path(target).expanduser()
    if requested_root.is_symlink():
        raise ValueError("target root must not be a symlink")
    root = requested_root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"target must be a directory: {root}")

    paths, _skipped, walk_errors = collect_files(root)
    if walk_errors:
        raise ValueError("source walk is incomplete: " + "; ".join(walk_errors[:5]))

    source_files: dict[str, bytes] = {}
    for source_path in paths:
        relative = source_path.relative_to(root).as_posix()
        source_files[relative] = _read_regular_bytes(source_path, MAX_FILE_BYTES)

    # Validate every expected digest before creating or modifying the candidate workspace.
    for change in validated["changes"]:
        relative = change["path"]
        if relative not in source_files:
            raise ValueError(f"change path is not an existing supported source file: {relative}")
        actual = hashlib.sha256(source_files[relative]).hexdigest()
        if actual != change["expected_sha256"]:
            raise ValueError(f"stale change plan for {relative}: expected source SHA-256 does not match")

    with tempfile.TemporaryDirectory(prefix="aegisforge-trial-") as temporary:
        workspace_root = Path(temporary)
        baseline_workspace = workspace_root / "baseline"
        candidate_workspace = workspace_root / "candidate"
        baseline_workspace.mkdir(mode=0o700)
        candidate_workspace.mkdir(mode=0o700)

        # Both scans derive from the exact same byte snapshot, avoiding baseline drift.
        for relative, contents in source_files.items():
            parts = PurePosixPath(relative).parts
            baseline_file = baseline_workspace.joinpath(*parts)
            candidate_file = candidate_workspace.joinpath(*parts)
            baseline_file.parent.mkdir(parents=True, exist_ok=True)
            candidate_file.parent.mkdir(parents=True, exist_ok=True)
            baseline_file.write_bytes(contents)
            candidate_file.write_bytes(contents)

        baseline = scan_directory(baseline_workspace)
        if baseline.errors:
            raise ValueError("baseline snapshot scan is incomplete: " + "; ".join(baseline.errors[:5]))

        for change in validated["changes"]:
            destination = candidate_workspace.joinpath(*PurePosixPath(change["path"]).parts)
            destination.write_bytes(change["replacement"].encode("utf-8"))

        candidate = scan_directory(candidate_workspace)
        introduced, resolved = _finding_delta(baseline.findings, candidate.findings)

        introduced_blockers = [
            item for item in introduced if item["severity"] in {"critical", "high"}
        ]
        if candidate.errors or introduced_blockers:
            decision = "rejected"
            reason = "candidate scan incomplete" if candidate.errors else "new critical/high findings were introduced"
        elif introduced:
            decision = "review"
            reason = "new lower-severity findings need human review"
        else:
            decision = "accepted"
            reason = "no new findings were detected by the configured static rules"

        return {
            "tool": "AegisForge",
            "engine": "controlled-trial",
            "schema_version": 1,
            "decision": decision,
            "reason": reason,
            "target": str(root),
            "changed_files": [item["path"] for item in validated["changes"]],
            "baseline": {"scanned_files": baseline.scanned_files, "finding_count": len(baseline.findings)},
            "candidate": {"scanned_files": candidate.scanned_files, "finding_count": len(candidate.findings)},
            "introduced_findings": introduced,
            "resolved_findings": resolved,
            "candidate_scan_errors": candidate.errors,
            "execution": {
                "project_code_executed": False,
                "shell_commands_executed": [],
                "source_project_modified": False,
                "workspace": "temporary copy; deleted after the trial",
            },
            "limitations": [
                "This is static analysis, not proof of exploitability or functional correctness.",
                "Only files supported by the current AegisForge scanner are copied into the trial workspace.",
                "A human must review and apply any accepted change to the original project.",
            ],
        }


def build_repair_plan(target: str | Path) -> dict[str, Any] | None:
    """Turn built-in preview-only repairs into a hash-checked trial plan."""
    from .repairs import propose_repairs

    requested_root = Path(target).expanduser()
    if requested_root.is_symlink():
        raise ValueError("target root must not be a symlink")
    root = requested_root.resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"target must be a directory: {root}")

    proposals = propose_repairs(root)
    if not proposals:
        return None

    changes: list[dict[str, str]] = []
    for proposal in proposals:
        relative = _safe_relative_path(proposal.path)
        source_path = root.joinpath(*PurePosixPath(relative).parts)
        raw = _read_regular_bytes(source_path, MAX_FILE_BYTES)
        try:
            original = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"repair source is not valid UTF-8 text: {relative}") from exc
        if original != proposal.original:
            raise ValueError(f"source changed after repair preview: {relative}")
        changes.append({
            "path": relative,
            "expected_sha256": hashlib.sha256(raw).hexdigest(),
            "replacement": proposal.replacement,
        })
    return validate_plan({"schema_version": PLAN_SCHEMA_VERSION, "changes": changes})


def run_repair_trial(target: str | Path) -> dict[str, Any]:
    """Generate built-in conservative repairs and test them without applying them."""
    root = Path(target).expanduser()
    plan = build_repair_plan(root)
    if plan is None:
        return {
            "tool": "AegisForge",
            "engine": "guided-repair-trial",
            "schema_version": 1,
            "decision": "no_changes",
            "reason": "no supported built-in repair proposals were found",
            "target": str(root.resolve()),
            "changed_files": [],
            "execution": {
                "project_code_executed": False,
                "shell_commands_executed": [],
                "source_project_modified": False,
                "workspace": "no trial workspace was needed",
            },
        }
    report = run_trial(root, plan)
    report["engine"] = "guided-repair-trial"
    report["planner"] = "built-in conservative repair rules; no external AI model"
    return report

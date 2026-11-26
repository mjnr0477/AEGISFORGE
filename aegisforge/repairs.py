"""Conservative, reviewable source repairs. Applying is always explicit."""
from __future__ import annotations

import ast
import difflib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .scanner import collect_files, read_source_file, scan_directory

DEBUG_ASSIGNMENT_RE = re.compile(r"^(\s*(?:DEBUG|debug)\s*[:=]\s*)(true|1|yes)\b", re.IGNORECASE)

@dataclass(frozen=True, slots=True)
class RepairProposal:
    path: str
    rule_ids: tuple[str, ...]
    original: str
    replacement: str
    diff: str

def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""

def _fix_debug_assignments(text: str) -> tuple[str, bool]:
    changed = False
    def replace(match: re.Match[str]) -> str:
        nonlocal changed
        token = match.group(2)
        normalized = token.lower()
        replacement = {"true": "false", "1": "0", "yes": "no"}[normalized]
        if token.isupper():
            replacement = replacement.upper()
        elif token[:1].isupper():
            replacement = replacement.capitalize()
        changed = True
        return match.group(1) + replacement
    lines = text.splitlines(keepends=True)
    rewritten = [DEBUG_ASSIGNMENT_RE.sub(replace, line, count=1) for line in lines]
    return "".join(rewritten), changed

def _fix_python_tls_verification(text: str) -> tuple[str, bool]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return text, False
    lines = text.splitlines(keepends=True)
    offsets: list[int] = []
    offset = 0
    for line in lines:
        offsets.append(offset)
        offset += len(line.encode("utf-8"))
    source = text.encode("utf-8")
    replacements: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _dotted_name(node.func).startswith(("requests.", "httpx.")):
            continue
        for keyword in node.keywords:
            value = keyword.value
            if keyword.arg != "verify" or not isinstance(value, ast.Constant) or value.value is not False:
                continue
            if not hasattr(value, "end_lineno") or not hasattr(value, "end_col_offset"):
                continue
            start = offsets[value.lineno - 1] + value.col_offset
            end = offsets[value.end_lineno - 1] + value.end_col_offset
            if source[start:end] == b"False":
                replacements.append((start, end))
    if not replacements:
        return text, False
    for start, end in sorted(set(replacements), reverse=True):
        source = source[:start] + b"True" + source[end:]
    return source.decode("utf-8"), True

def _repair_text(path: Path, relative_path: str, text: str) -> RepairProposal | None:
    replacement = text
    rule_ids: list[str] = []
    replacement, debug_changed = _fix_debug_assignments(replacement)
    if debug_changed:
        rule_ids.append("AF-CFG-001")
    if path.suffix.lower() in {".py", ".pyw"}:
        replacement, tls_changed = _fix_python_tls_verification(replacement)
        if tls_changed:
            rule_ids.append("AF-PY-003")
    if not rule_ids or replacement == text:
        return None
    diff = "".join(difflib.unified_diff(
        text.splitlines(keepends=True),
        replacement.splitlines(keepends=True),
        fromfile=f"a/{relative_path}",
        tofile=f"b/{relative_path}",
    ))
    return RepairProposal(relative_path, tuple(rule_ids), text, replacement, diff)

def propose_repairs(target: str | Path) -> list[RepairProposal]:
    """Build supported local patch proposals without changing files."""
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Target must be a directory: {root}")
    paths, _skipped, errors = collect_files(root)
    if errors:
        raise ValueError("repair preview requires a complete file walk: " + "; ".join(errors[:5]))
    proposals: list[RepairProposal] = []
    for path in paths:
        try:
            text = read_source_file(path)
        except (OSError, UnicodeError, ValueError):
            continue
        relative_path = path.relative_to(root).as_posix()
        proposal = _repair_text(path, relative_path, text)
        if proposal is not None:
            proposals.append(proposal)
    return proposals

def _reject_symlink_components(root: Path, candidate: Path) -> None:
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("repair path is outside scan root") from exc
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RuntimeError(f"refusing symlink component in repair path: {current}")

def apply_repairs(
    target: str | Path,
    proposals: list[RepairProposal],
    backup_dir: str | Path | None = None,
) -> list[Path]:
    """Apply previewed proposals, back up originals, and roll back failed post-checks."""
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Target must be a directory: {root}")
    if not proposals:
        return []
    validated: list[tuple[Path, RepairProposal]] = []
    seen_paths: set[str] = set()
    for proposal in proposals:
        relative = PurePosixPath(proposal.path)
        if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts) or "\\" in proposal.path:
            raise RuntimeError(f"Repair proposal path must be a safe relative path: {proposal.path}")
        normalized = relative.as_posix()
        if normalized in seen_paths:
            raise RuntimeError(f"Duplicate repair proposal path: {proposal.path}")
        seen_paths.add(normalized)
        candidate = root.joinpath(*relative.parts)
        _reject_symlink_components(root, candidate)
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise RuntimeError(f"Refusing path outside scan root: {proposal.path}") from exc
        if not resolved.is_file():
            raise RuntimeError(f"Source file is missing: {proposal.path}")
        current = read_source_file(resolved)
        if current != proposal.original:
            raise RuntimeError(f"Source changed since preview: {proposal.path}")
        validated.append((resolved, proposal))

    if backup_dir is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_base = root / ".aegisforge" / "backups"
        for component in (root / ".aegisforge", backup_base):
            if component.is_symlink():
                raise RuntimeError(f"Refusing backup directory symlink outside or within target: {component}")
        backup_root = backup_base / stamp
        try:
            backup_root.resolve(strict=False).relative_to(root)
        except ValueError as exc:
            raise RuntimeError(f"Refusing backup directory outside target root: {backup_root}") from exc
    else:
        backup_root = Path(backup_dir).expanduser().resolve()

    backups: list[Path] = []
    for path, proposal in validated:
        backup = backup_root.joinpath(*PurePosixPath(proposal.path).parts)
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)
        backups.append(backup)

    written: list[Path] = []
    try:
        for (path, proposal), backup in zip(validated, backups):
            temp_name: str | None = None
            try:
                _reject_symlink_components(root, path)
                if read_source_file(path) != proposal.original:
                    raise RuntimeError(f"Source changed since preview: {proposal.path}")
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
                    temp_name = handle.name
                    handle.write(proposal.replacement)
                    handle.flush()
                    os.fsync(handle.fileno())
                shutil.copystat(backup, temp_name)
                os.replace(temp_name, path)
                written.append(path)
            finally:
                if temp_name and os.path.exists(temp_name):
                    os.unlink(temp_name)

        verification = scan_directory(root)
        remaining = [
            f"{finding.path}:{finding.line} ({finding.rule_id})"
            for _path, proposal in validated
            for finding in verification.findings
            if finding.path == proposal.path and finding.rule_id in proposal.rule_ids
        ]
        if verification.errors:
            raise RuntimeError("Repair verification scan was incomplete: " + "; ".join(verification.errors[:5]))
        if remaining:
            raise RuntimeError("Repair verification failed; targeted finding(s) remain: " + ", ".join(sorted(set(remaining))))
    except (OSError, RuntimeError, UnicodeError):
        for (path, _proposal), backup in zip(validated, backups):
            if path in written:
                shutil.copy2(backup, path)
        raise
    return backups

"""Bounded filesystem traversal that avoids symlinks and never executes source."""
import os
import stat
from pathlib import Path
from .analyzers import analyze_python, analyze_text
from .models import Finding, ScanResult, SEVERITY_ORDER

SUPPORTED = {".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".go", ".java", ".cs", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bash", ".sql", ".tf", ".xml", ".properties"}
SPECIAL = {"Dockerfile", "Containerfile", ".env", ".env.local", ".env.production"}
EXCLUDED = {".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "__pycache__", "dist", "build", ".next", ".aegisforge"}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 10_000
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_DIRECTORIES = 25_000

class UnsafeScanFileError(ValueError):
    pass

def should_scan(path: Path) -> bool:
    return path.name in SPECIAL or path.suffix.lower() in SUPPORTED

def _regular_metadata(path: Path) -> os.stat_result:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeScanFileError(f"refusing non-regular or changed file: {path}")
    return info

def read_source_file(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    before = _regular_metadata(path)
    if before.st_size > max_bytes:
        raise ValueError(f"file exceeds {max_bytes} bytes: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise UnsafeScanFileError(f"refusing changed file: {path}")
        if opened.st_size > max_bytes:
            raise ValueError(f"file exceeds {max_bytes} bytes: {path}")
        chunks, remaining = [], max_bytes + 1
        while remaining:
            block = os.read(fd, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            raise ValueError(f"file exceeds {max_bytes} bytes: {path}")
        return raw.decode("utf-8", errors="replace")
    finally:
        os.close(fd)

def collect_files(root: Path):
    files, skipped, errors = [], 0, []
    total, entries, directories = 0, 0, 0
    for current, dirs, names in os.walk(root, followlinks=False):
        directories += 1
        if directories > MAX_DIRECTORIES:
            errors.append(f"directory limit reached ({MAX_DIRECTORIES})")
            break
        allowed_dirs = sorted(n for n in dirs if n not in EXCLUDED and not (Path(current)/n).is_symlink())
        items = sorted([(n, True) for n in allowed_dirs] + [(n, False) for n in names])
        remaining = MAX_ENTRIES - entries
        if remaining <= 0 and items:
            errors.append(f"entry limit reached ({MAX_ENTRIES})")
            break
        truncated = len(items) > remaining
        items = items[:remaining]
        dirs[:] = [n for n, is_dir in items if is_dir]
        entries += len(items)
        for name, is_dir in items:
            if is_dir:
                continue
            path = Path(current)/name
            if not should_scan(path):
                skipped += 1
                continue
            try:
                info = _regular_metadata(path)
                if info.st_size > MAX_FILE_BYTES:
                    skipped += 1
                    errors.append(f"file size limit exceeded: {path}")
                    continue
            except (OSError, UnsafeScanFileError) as exc:
                skipped += 1
                errors.append(f"{path}: {exc}")
                continue
            if len(files) >= MAX_FILES or total + info.st_size > MAX_TOTAL_BYTES:
                errors.append("scan resource budget reached; remaining files were not scanned")
                return files, skipped, errors
            files.append(path)
            total += info.st_size
        if truncated:
            errors.append(f"entry limit reached ({MAX_ENTRIES})")
            break
    return files, skipped, errors

def scan_directory(target: str | Path) -> ScanResult:
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"target does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"target must be a directory: {root}")
    paths, skipped, errors = collect_files(root)
    findings: list[Finding] = []
    scanned = 0
    for path in paths:
        try:
            source = read_source_file(path)
            rel = path.relative_to(root).as_posix()
            scanned += 1
            findings.extend(analyze_text(source, rel))
            if path.suffix.lower() in {".py", ".pyw"}:
                findings.extend(analyze_python(source, rel))
        except (OSError, ValueError) as exc:
            skipped += 1
            errors.append(f"{path}: {exc}")
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.path, f.line, f.rule_id))
    unique, seen = [], set()
    for item in findings:
        key = (item.rule_id, item.path, item.line, item.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return ScanResult(str(root), scanned, skipped, unique, errors)

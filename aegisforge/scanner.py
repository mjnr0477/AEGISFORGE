"""Bounded filesystem traversal that avoids symlinks and never executes source."""
import os
import stat
from pathlib import Path
from .analyzers import analyze_python, analyze_text
from .dataflow import analyze_python_flows
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

def _supports_safe_dir_fd_open() -> bool:
    return (
        os.open in getattr(os, "supports_dir_fd", set())
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )


def _open_directory_chain(directory: Path) -> int:
    """Open an absolute directory one component at a time without following links."""
    absolute = Path(os.path.abspath(directory))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(absolute.anchor or os.sep, flags)
    try:
        for component in absolute.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


def _open_file_descriptor(path: Path, root: Path | None = None) -> int:
    """Open a regular-file candidate relative to a pinned directory descriptor."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if not _supports_safe_dir_fd_open():
        before = _regular_metadata(path)
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            os.close(fd)
            raise UnsafeScanFileError(f"refusing changed file: {path}")
        return fd

    if root is None:
        root_path = Path(path).parent.resolve()
        relative = Path(path).name
        directory_parts = ()
    else:
        root_path = Path(root).expanduser().resolve()
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = root_path / candidate
        try:
            relative_path = candidate.relative_to(root_path)
        except ValueError as exc:
            raise UnsafeScanFileError(f"refusing file outside scan root: {path}") from exc
        if not relative_path.parts or any(part in {"", ".", ".."} for part in relative_path.parts):
            raise UnsafeScanFileError(f"refusing unsafe file path: {path}")
        relative = relative_path.parts[-1]
        directory_parts = relative_path.parts[:-1]

    directory_fd = _open_directory_chain(root_path)
    try:
        for component in directory_parts:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(relative, flags, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def read_source_file(
    path: Path,
    max_bytes: int = MAX_FILE_BYTES,
    *,
    root: Path | None = None,
) -> str:
    """Read a bounded regular file without traversing symlinked path components.

    When a scan root is supplied, every path component below it is opened
    relative to a pinned directory descriptor, preventing a swapped directory
    symlink from redirecting the read outside that root.
    """
    fd = _open_file_descriptor(Path(path), root=root)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafeScanFileError(f"refusing non-regular file: {path}")
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
            source = read_source_file(path, root=root)
            rel = path.relative_to(root).as_posix()
            scanned += 1
            findings.extend(analyze_text(source, rel))
            if path.suffix.lower() in {".py", ".pyw"}:
                try:
                    findings.extend(analyze_python(source, rel))
                    findings.extend(analyze_python_flows(source, rel))
                except SyntaxError as exc:
                    location = f" at line {exc.lineno}" if exc.lineno else ""
                    errors.append(
                        f"{rel}: Python syntax error{location}; AST analysis skipped: {exc.msg}"
                    )
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

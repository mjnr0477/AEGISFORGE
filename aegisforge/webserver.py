"""Loopback-only browser console with strict, non-executing ZIP inspection."""
from __future__ import annotations

import ipaddress
import json
import socket
import stat
import tempfile
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from .scanner import EXCLUDED, MAX_ENTRIES, MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES, scan_directory, should_scan
from .project_map import build_project_map

MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = min(MAX_ENTRIES, 10_000)
MAX_COMPRESSION_RATIO = 200
STATIC_ASSETS = {
    "/": ("web/index.html", "text/html; charset=utf-8"),
    "/index.html": ("web/index.html", "text/html; charset=utf-8"),
    "/app.css": ("web/app.css", "text/css; charset=utf-8"),
    "/app.js": ("web/app.js", "text/javascript; charset=utf-8"),
}

class ArchiveValidationError(ValueError):
    """An uploaded ZIP cannot be safely inspected under the local limits."""

def _validate_archive_name(name: str, is_directory: bool) -> tuple[str, tuple[str, ...]]:
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise ArchiveValidationError(f"unsafe archive path: {name!r}")
    raw = name[:-1] if is_directory and name.endswith("/") else name
    parts = raw.split("/")
    if (
        not raw
        or len(raw) > 240
        or any(part in {"", ".", ".."} for part in parts)
        or any(":" in part for part in parts)
        or any(part.endswith((" ", ".")) for part in parts)
        or any(part.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))} for part in parts)
    ):
        raise ArchiveValidationError(f"unsafe archive path: {name!r}")
    return "/".join(parts), tuple(parts)

def _validate_zip_info(info: zipfile.ZipInfo) -> tuple[str, tuple[str, ...], bool]:
    is_directory = info.is_dir()
    name, parts = _validate_archive_name(info.filename, is_directory)
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if file_type == stat.S_IFLNK:
        raise ArchiveValidationError(f"symlink entry is not allowed: {name}")
    allowed_type = stat.S_IFDIR if is_directory else stat.S_IFREG
    if file_type not in (0, allowed_type):
        raise ArchiveValidationError(f"special filesystem entry is not allowed: {name}")
    if info.flag_bits & 0x1:
        raise ArchiveValidationError(f"encrypted ZIP entries are not supported: {name}")
    return name, parts, is_directory

def _json_result(result: Any, project_map: Any) -> dict[str, Any]:
    return {
        "root": "uploaded-project",
        "scanned_files": result.scanned_files,
        "skipped_files": result.skipped_files,
        "summary": result.summary(),
        "project_map": project_map.to_dict(),
        "findings": [finding.to_dict() for finding in result.findings],
        "errors": list(result.errors),
    }

def scan_archive_bytes(archive_bytes: bytes) -> dict[str, Any]:
    """Safely extract supported source files to a temporary folder and scan them."""
    if not isinstance(archive_bytes, bytes) or not archive_bytes:
        raise ArchiveValidationError("archive is empty")
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ArchiveValidationError(f"archive exceeds the {MAX_ARCHIVE_BYTES}-byte limit")
    try:
        archive = zipfile.ZipFile(BytesIO(archive_bytes), "r")
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise ArchiveValidationError("invalid ZIP archive") from exc

    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ArchiveValidationError(f"archive entry limit exceeded ({MAX_ARCHIVE_ENTRIES})")
        seen: set[str] = set()
        extracted_files = 0
        total_uncompressed = 0
        with tempfile.TemporaryDirectory(prefix="aegisforge-upload-") as temporary:
            root = Path(temporary).resolve()
            for info in infos:
                name, parts, is_directory = _validate_zip_info(info)
                canonical = name.casefold()
                if canonical in seen:
                    raise ArchiveValidationError(f"duplicate archive path: {name}")
                seen.add(canonical)
                if any(part.casefold() in EXCLUDED for part in parts):
                    continue
                if is_directory or not should_scan(Path(name)):
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    raise ArchiveValidationError(f"source file exceeds the {MAX_FILE_BYTES}-byte limit: {name}")
                if info.file_size < 0 or info.compress_size < 0:
                    raise ArchiveValidationError(f"invalid ZIP entry size: {name}")
                if info.file_size and (info.compress_size == 0 or info.file_size > info.compress_size * MAX_COMPRESSION_RATIO):
                    raise ArchiveValidationError(f"compression ratio limit exceeded: {name}")
                extracted_files += 1
                total_uncompressed += info.file_size
                if extracted_files > MAX_FILES:
                    raise ArchiveValidationError(f"source file limit exceeded ({MAX_FILES})")
                if total_uncompressed > MAX_TOTAL_BYTES:
                    raise ArchiveValidationError(f"total extracted source limit exceeded ({MAX_TOTAL_BYTES} bytes)")
                destination = root.joinpath(*parts)
                try:
                    destination.resolve(strict=False).relative_to(root)
                except ValueError as exc:
                    raise ArchiveValidationError(f"unsafe archive path: {name}") from exc
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with archive.open(info, "r") as source:
                        content = source.read(MAX_FILE_BYTES + 1)
                except (OSError, RuntimeError, zipfile.BadZipFile, EOFError) as exc:
                    raise ArchiveValidationError(f"could not read ZIP entry: {name}") from exc
                if len(content) != info.file_size or len(content) > MAX_FILE_BYTES:
                    raise ArchiveValidationError(f"ZIP entry size mismatch: {name}")
                destination.write_bytes(content)
            result = scan_directory(root)
            project_map = build_project_map(root)
            return _json_result(result, project_map)

class AegisForgeLocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

class AegisForgeRequestHandler(BaseHTTPRequestHandler):
    server_version = "AegisForgeLocal/1"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format: str, *args: object) -> None:
        # Avoid writing client-supplied paths, headers, or report data to local logs.
        return

    def _allowed_hosts(self) -> set[str]:
        port = self.server.server_port
        return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _check_host(self) -> bool:
        host = self.headers.get("Host", "").strip().lower()
        return host in self._allowed_hosts()

    def _check_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return False
        parsed = urlsplit(origin)
        return parsed.scheme == "http" and parsed.netloc.lower() == self.headers.get("Host", "").strip().lower() and not parsed.username and not parsed.password and parsed.path in ("", "/") and not parsed.query and not parsed.fragment

    def do_GET(self) -> None:
        if not self._check_host():
            self._send_json(403, {"error": "Only loopback Host headers are accepted."})
            return
        path = urlsplit(self.path).path
        asset = STATIC_ASSETS.get(path)
        if asset is None:
            self._send_json(404, {"error": "Not found."})
            return
        resource, content_type = asset
        try:
            body = files("aegisforge").joinpath(*resource.split("/")).read_bytes()
        except (OSError, ModuleNotFoundError) as exc:
            self._send_json(500, {"error": "Local interface asset is unavailable."})
            return
        self._send_bytes(200, body, content_type)

    def do_POST(self) -> None:
        if not self._check_host():
            self._send_json(403, {"error": "Only loopback Host headers are accepted."})
            return
        if not self._check_origin():
            self._send_json(403, {"error": "Same-origin local requests are required."})
            return
        if urlsplit(self.path).path != "/api/scan":
            self._send_json(404, {"error": "Not found."})
            return
        if self.headers.get("Transfer-Encoding"):
            self._send_json(400, {"error": "Chunked transfer encoding is not supported."})
            return
        if self.headers.get_content_type() != "application/zip":
            self._send_json(415, {"error": "Send a ZIP archive using application/zip."})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_json(411, {"error": "A valid Content-Length header is required."})
            return
        if length <= 0:
            self._send_json(400, {"error": "Archive is empty."})
            return
        if length > MAX_ARCHIVE_BYTES:
            self._send_json(413, {"error": "Archive exceeds the 25 MB request limit."})
            return
        try:
            body = self.rfile.read(length)
        except (TimeoutError, OSError):
            self._send_json(408, {"error": "Upload timed out."})
            return
        if len(body) != length:
            self._send_json(400, {"error": "Upload ended before the declared content length."})
            return
        try:
            result = scan_archive_bytes(body)
        except ArchiveValidationError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except (OSError, ValueError, RuntimeError) as exc:
            self._send_json(422, {"error": f"Local scan could not be completed: {exc}"})
            return
        self._send_json(200, result)

def create_server(host: str = "127.0.0.1", port: int = 8765) -> AegisForgeLocalServer:
    """Create an HTTP server bound exclusively to an IPv4/IPv6 loopback address."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("host must be a loopback IP address (127.0.0.1 or ::1)") from exc
    if not address.is_loopback:
        raise ValueError("AegisForge's browser console may only bind to loopback addresses.")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 to 65535")
    server_class = type(
        "AegisForgeLoopbackHTTPServer",
        (AegisForgeLocalServer,),
        {"address_family": socket.AF_INET6 if address.version == 6 else socket.AF_INET},
    )
    return server_class((str(address), port), AegisForgeRequestHandler)

def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = create_server(host, port)
    printable_host = f"[{host}]" if ":" in host else host
    print(f"AegisForge local workbench: http://{printable_host}:{server.server_port}")
    print("Local-only server. Keep this terminal open; press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AegisForge local workbench.")
    finally:
        server.server_close()

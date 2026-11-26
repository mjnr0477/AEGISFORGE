"""Static analyzers. Source files are parsed/read but never imported or executed."""
import ast
import re
from pathlib import Path
from .models import Finding
from .rules import RULE_MAP

SECRET_RE = re.compile(r"""(?i)\b([A-Z0-9_.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|credential|token)[A-Z0-9_.-]*)\b\s*[:=]\s*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})'|([^\s,;#}\]]{8,}))""")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
PLACEHOLDERS = {"example", "changeme", "change-me", "placeholder", "redacted", "dummy", "test", "testing", "none", "null", "true", "false"}
BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{12,}")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GH_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")
AUTH_RE = re.compile(r"(?i)(\b(?:proxy-)?authorization\s*:\s*)[^\r\n]+")
URL_AUTH_RE = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/@\s:]+:[^/\s]+@")
DEBUG_RE = re.compile(r"(?im)^\s*(?:DEBUG|debug)\s*[:=]\s*(?:true|1|yes)\b")
PRIV_RE = re.compile(r"(?i)^\s*[\"']?privileged[\"']?\s*:\s*true\b")
HOSTPATH_RE = re.compile(r"(?i)^\s*[\"']?hostPath[\"']?\s*:")
DOCKER_ROOT_RE = re.compile(r"(?i)^\s*USER\s+(?:root|0)\s*(?:#.*)?$")

def sanitize_evidence(value: str) -> str:
    """Remove secret values and common credential formats from report snippets."""
    def mask_assignment(match: re.Match[str]) -> str:
        vals = match.group(2, 3, 4)
        raw = next((v for v in vals if v is not None), "")
        if raw.strip().lower() in {"true", "false", "none", "null"}:
            return match.group(0)
        return f"{match.group(1)}=***"
    value = SECRET_RE.sub(mask_assignment, value)
    value = AUTH_RE.sub(r"\1***", value)
    value = URL_AUTH_RE.sub(r"\1***@", value)
    value = BEARER_RE.sub(r"\1***", value)
    for pattern in (JWT_RE, AWS_RE, GH_RE):
        value = pattern.sub("***", value)
    return value[:180]

def _finding(rule_id: str, path: str, line: int, column: int, evidence: str, confidence: str = "medium") -> Finding:
    rule = RULE_MAP[rule_id]
    return Finding(rule.rule_id, rule.severity, rule.title, rule.description, path,
                   max(1, line), max(1, column), sanitize_evidence(evidence),
                   rule.remediation, confidence, rule.cwe)

def analyze_text(text: str, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    suffix = Path(rel_path).suffix.lower()
    name = Path(rel_path).name.lower()
    for n, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if PRIV_RE.search(line):
            findings.append(_finding("AF-CON-001", rel_path, n, 1, stripped, "high"))
        if HOSTPATH_RE.search(line):
            findings.append(_finding("AF-CON-002", rel_path, n, 1, stripped, "high"))
        if (name in {"dockerfile", "containerfile"} or suffix == ".dockerfile") and DOCKER_ROOT_RE.search(line):
            findings.append(_finding("AF-DKR-001", rel_path, n, 1, stripped, "medium"))
        for match in SECRET_RE.finditer(line):
            value = next((v for v in match.group(2, 3, 4) if v is not None), "")
            normalized = value.strip().lower()
            if normalized in PLACEHOLDERS or normalized.startswith(("your_", "replace_", "<")):
                continue
            if match.group(4) is not None and suffix not in {".env", ".ini", ".cfg", ".conf", ".properties", ".toml", ".yaml", ".yml", ".sh"} and not name.startswith(".env"):
                continue
            findings.append(_finding("AF-SEC-001", rel_path, n, match.start() + 1,
                                     f"{match.group(1)}=***", "medium"))
        if PRIVATE_KEY_RE.search(line):
            findings.append(_finding("AF-SEC-002", rel_path, n, 1, "private-key material present", "high"))
        if DEBUG_RE.search(line):
            findings.append(_finding("AF-CFG-001", rel_path, n, 1, stripped, "medium"))
    if re.search(r"(?i)(?:allow-origin|allowed-origins|cors_origins)[^\r\n]{0,80}\*", text) and re.search(r"(?i)(?:allow-credentials|supports_credentials|credentials)\s*[:=]\s*(?:true|1)", text):
        line = next((i for i, row in enumerate(lines, 1) if re.search(r"(?i)(?:allow-origin|allowed-origins|cors_origins)[^\r\n]{0,80}\*", row)), 1)
        findings.append(_finding("AF-CFG-002", rel_path, line, 1, lines[line-1].strip(), "medium"))
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        for n, line in enumerate(lines, 1):
            if re.search(r"\beval\s*\(|\bnew\s+Function\s*\(", line):
                findings.append(_finding("AF-JS-001", rel_path, n, 1, line.strip(), "medium"))
            if re.search(r"\.innerHTML\s*=", line):
                findings.append(_finding("AF-JS-002", rel_path, n, 1, line.strip(), "low"))
    return findings

class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, path: str, lines: list[str]):
        self.path, self.lines, self.findings = path, lines, []
    @staticmethod
    def _name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = _PythonVisitor._name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""
    def add(self, rule_id: str, node: ast.AST, confidence: str = "medium") -> None:
        line = getattr(node, "lineno", 1)
        evidence = self.lines[line-1].strip() if 0 < line <= len(self.lines) else "source expression"
        self.findings.append(_finding(rule_id, self.path, line, getattr(node, "col_offset", 0)+1, evidence, confidence))
    def visit_Call(self, node: ast.Call) -> None:
        func = self._name(node.func)
        if func in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self.add("AF-PY-001", node, "high")
        if func in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}:
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                self.add("AF-PY-002", node, "high")
        if func.startswith(("requests.", "httpx.")) and any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords):
            self.add("AF-PY-003", node, "high")
        if func in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"}:
            self.add("AF-PY-004", node, "high")
        if func.endswith(".execute") and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
            self.add("AF-PY-005", node, "medium")
        if func in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
            self.add("AF-PY-006", node, "low")
        self.generic_visit(node)

def analyze_python(text: str, rel_path: str) -> list[Finding]:
    try:
        tree = ast.parse(text, filename=rel_path)
    except (SyntaxError, ValueError):
        return []
    visitor = _PythonVisitor(rel_path, text.splitlines())
    visitor.visit(tree)
    return visitor.findings

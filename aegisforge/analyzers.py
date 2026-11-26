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
ALLOW_PRIV_ESC_RE = re.compile(r"""(?i)^\s*["']?allow[_-]?privilege[_-]?escalation["']?\s*:\s*true\b""")

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


def _terraform_masks(text: str) -> tuple[str, str]:
    """Mask comments and quoted strings for safe, brace-aware Terraform scanning."""
    clean, structure = list(text), list(text)
    quote = None
    escaped = False
    line_comment = False
    block_comment = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            else:
                clean[i] = structure[i] = " "
        elif block_comment:
            if ch == "*" and nxt == "/":
                clean[i] = clean[i + 1] = " "
                structure[i] = structure[i + 1] = " "
                i += 1
                block_comment = False
            elif ch != "\n":
                clean[i] = structure[i] = " "
        elif quote:
            structure[i] = " "
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        elif ch == '"':
            quote = ch
            structure[i] = " "
        elif ch == "#" or (ch == "/" and nxt == "/"):
            line_comment = True
            clean[i] = structure[i] = " "
            if ch == "/":
                clean[i + 1] = structure[i + 1] = " "
                i += 1
        elif ch == "/" and nxt == "*":
            block_comment = True
            clean[i] = clean[i + 1] = " "
            structure[i] = structure[i + 1] = " "
            i += 1
        i += 1
    return "".join(clean), "".join(structure)

def _matching_hcl_brace(masked: str, opening: int) -> int | None:
    depth = 0
    for position in range(opening, len(masked)):
        if masked[position] == "{":
            depth += 1
        elif masked[position] == "}":
            depth -= 1
            if depth == 0:
                return position
    return None

def _terraform_ingress_findings(text: str, rel_path: str) -> list[Finding]:
    """Flag only literal public SSH/RDP ingress inside AWS security-group resources."""
    clean, structure = _terraform_masks(text)
    findings: list[Finding] = []
    source_lines = text.splitlines()
    resource_re = re.compile(r'(?m)^\s*resource\s+"aws_security_group"\s+"[^"\n]+"\s*\{')
    for resource in resource_re.finditer(clean):
        resource_open = structure.find("{", resource.start(), resource.end())
        resource_close = _matching_hcl_brace(structure, resource_open)
        if resource_open < 0 or resource_close is None:
            continue
        body = structure[resource_open + 1:resource_close]
        for ingress in re.finditer(r"\bingress\s*\{", body):
            opening = resource_open + 1 + body.find("{", ingress.start(), ingress.end())
            closing = _matching_hcl_brace(structure, opening)
            if closing is None or closing > resource_close:
                continue
            block = clean[opening + 1:closing]
            from_port = re.search(r"(?m)^\s*from_port\s*=\s*(-?\d+)\s*(?:\n|$)", block)
            to_port = re.search(r"(?m)^\s*to_port\s*=\s*(-?\d+)\s*(?:\n|$)", block)
            protocol = re.search(r'(?m)^\s*protocol\s*=\s*"([^"]+)"\s*(?:\n|$)', block)
            public_range = re.search(r'(?s)\b(?:cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*"(?:0\.0\.0\.0/0|::/0)"', block)
            if not (from_port and to_port and protocol and public_range):
                continue
            start, end = int(from_port.group(1)), int(to_port.group(1))
            proto = protocol.group(1).lower()
            if start > end or proto not in {"tcp", "-1"}:
                continue
            exposed = []
            if start <= 22 <= end:
                exposed.append("SSH (22)")
            if start <= 3389 <= end:
                exposed.append("RDP (3389)")
            if not exposed:
                continue
            line = text.count("\n", 0, resource_open + 1 + ingress.start()) + 1
            evidence = source_lines[line - 1].strip() if line <= len(source_lines) else "ingress {"
            findings.append(_finding("AF-TF-001", rel_path, line, 1, evidence, "high"))
    return findings

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
        if ALLOW_PRIV_ESC_RE.search(line):
            findings.append(_finding("AF-CON-003", rel_path, n, 1, stripped, "high"))
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
    if suffix == ".tf":
        findings.extend(_terraform_ingress_findings(text, rel_path))
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
    def visit_Compare(self, node: ast.Compare) -> None:
        operands = [node.left, *node.comparators]
        names = [self._name(item).lower() for item in operands]
        signature_context = any("signature" in name for name in names)
        expected_value = any(any(marker in name for marker in ("expected", "computed", "calculated", "digest", "hmac", "mac")) for name in names)
        equality = any(isinstance(operator, (ast.Eq, ast.NotEq)) for operator in node.ops)
        if signature_context and expected_value and equality:
            self.add("AF-PAY-001", node, "medium")
        self.generic_visit(node)

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
        if func == "yaml.unsafe_load":
            self.add("AF-PY-007", node, "high")
        elif func == "yaml.load":
            safe_loader = any(k.arg == "Loader" and self._name(k.value).endswith("SafeLoader") for k in node.keywords)
            if not safe_loader:
                self.add("AF-PY-007", node, "high")
        if func.endswith(".execute") and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
            self.add("AF-PY-005", node, "medium")
        if func in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
            self.add("AF-PY-006", node, "low")
        self.generic_visit(node)

def analyze_python(text: str, rel_path: str) -> list[Finding]:
    """Analyze Python syntax; parsing failures are raised to the scanner as gaps."""
    tree = ast.parse(text, filename=rel_path)
    visitor = _PythonVisitor(rel_path, text.splitlines())
    visitor.visit(tree)
    return visitor.findings

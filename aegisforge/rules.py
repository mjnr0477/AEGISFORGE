"""Conservative initial rule catalog; findings require human validation."""
from .models import Rule

RULES = [
    Rule("AF-PY-001", "Dynamic code evaluation", "high", "eval() or exec() evaluates code dynamically and can execute untrusted input.", "Avoid eval/exec. Parse data and dispatch through explicit, validated operations.", "CWE-95"),
    Rule("AF-PY-002", "Subprocess shell enabled", "high", "A subprocess call enables a command shell, increasing command-injection risk.", "Pass an argument list and keep shell=False. Validate each argument.", "CWE-78"),
    Rule("AF-PY-003", "TLS verification disabled", "high", "An HTTP client disables TLS certificate verification.", "Keep certificate verification enabled and configure a trusted CA bundle.", "CWE-295"),
    Rule("AF-PY-004", "Unsafe pickle deserialization", "high", "pickle.load/loads can execute attacker-controlled code.", "Never load untrusted pickle data; prefer schema-validated JSON.", "CWE-502"),
    Rule("AF-PY-005", "Possible SQL injection", "high", "A database execute call receives a formatted or concatenated query string.", "Use parameterized queries and bind values separately.", "CWE-89"),
    Rule("AF-PY-006", "Weak hash algorithm", "low", "MD5 or SHA-1 is used in code.", "Use a modern cryptographic hash for integrity and Argon2id/scrypt/bcrypt for passwords.", "CWE-328"),
    Rule("AF-SEC-001", "Possible hard-coded credential", "high", "A credential-like assignment contains a non-placeholder literal.", "Rotate exposed credentials and move secrets into a protected secret manager.", "CWE-798"),
    Rule("AF-SEC-002", "Private key material", "critical", "A PEM private-key header appears in a scanned file.", "Remove the key, revoke or rotate it, and store replacement material securely.", "CWE-321"),
    Rule("AF-CFG-001", "Debug mode enabled", "medium", "A configuration appears to enable debug mode.", "Disable debug mode in production and avoid exposing detailed errors.", "CWE-489"),
    Rule("AF-CFG-002", "Wildcard CORS with credentials", "high", "Wildcard CORS and credentialed requests occur in the same file.", "Use an explicit trusted-origin allowlist; do not combine wildcard origins with credentials.", "CWE-942"),
    Rule("AF-JS-001", "Dynamic JavaScript evaluation", "high", "eval() or the Function constructor dynamically evaluates JavaScript.", "Avoid dynamic evaluation; use explicit operations and treat input as data.", "CWE-95"),
    Rule("AF-JS-002", "Potential unsafe HTML injection", "medium", "Code assigns to innerHTML, which may interpret untrusted markup.", "Prefer textContent or safe DOM APIs; sanitize intentionally supported HTML.", "CWE-79"),
    Rule("AF-CON-001", "Privileged container", "high", "A container configuration enables privileged mode.", "Disable privileged mode and grant only required Linux capabilities.", "CWE-250"),
    Rule("AF-CON-002", "Host filesystem mount", "high", "A container configuration declares hostPath.", "Prefer scoped persistent volumes and read-only mounts.", "CWE-284"),
    Rule("AF-DKR-001", "Docker runs as root", "medium", "A Dockerfile explicitly selects root as runtime user.", "Create a dedicated unprivileged user and select it with USER.", "CWE-250"),
]
RULE_MAP = {item.rule_id: item for item in RULES}

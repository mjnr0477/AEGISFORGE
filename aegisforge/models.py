"""Immutable data models shared by analyzers and report renderers."""
from dataclasses import asdict, dataclass
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    description: str
    remediation: str
    cwe: str | None = None

@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    path: str
    line: int
    column: int
    evidence: str
    remediation: str
    confidence: str = "medium"
    cwe: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class ScanResult:
    root: str
    scanned_files: int
    skipped_files: int
    findings: list[Finding]
    errors: list[str]

    def summary(self) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITY_ORDER}
        for item in self.findings:
            counts[item.severity] = counts.get(item.severity, 0) + 1
        return counts

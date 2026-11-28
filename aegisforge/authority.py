"""Default-deny capability authorization and tamper-evident decision logging.

The kernel decides whether a caller may perform a named operation on one exact
resource. It does not perform operations, discover adapters, or grant access
implicitly. Hosts must authenticate approvers before issuing one-time approvals.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_]*)+$")
ZERO_HASH = "0" * 64
MAX_APPROVAL_TTL_SECONDS = 900
MAX_OUTSTANDING_APPROVALS = 4096


class AuthorityError(RuntimeError):
    """Base exception for invalid authority configuration or audit state."""


class AuditLogIntegrityError(AuthorityError):
    """Raised when an existing decision log is malformed or its chain is broken."""


@dataclass(frozen=True, slots=True)
class CapabilitySpec:
    name: str
    description: str
    mutates: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not CAPABILITY_RE.fullmatch(self.name):
            raise ValueError("capability name must be a dotted lowercase identifier")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("capability description must not be empty")
        if not isinstance(self.mutates, bool):
            raise ValueError("capability mutates flag must be boolean")


@dataclass(frozen=True, slots=True)
class Grant:
    """A time-limited grant for one subject, capability, and exact resource."""

    subject: str
    capability: str
    resource: str
    expires_at: datetime

    def __post_init__(self) -> None:
        _validate_label(self.subject, "subject", 256)
        _validate_label(self.resource, "resource", 1024)
        if not isinstance(self.capability, str) or not CAPABILITY_RE.fullmatch(self.capability):
            raise ValueError("grant capability must be a dotted lowercase identifier")
        _require_aware(self.expires_at, "grant expires_at")


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    subject: str
    capability: str
    resource: str
    reason: str
    audit_sequence: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _Approval:
    subject: str
    capability: str
    resource: str
    approver: str
    expires_at: datetime


def _validate_label(value: str, name: str, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{name} must be a non-empty string of at most {maximum} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} must not contain control characters")


def _require_aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class _AuditTrail:
    """Sequential JSONL hash chain; detects edits/reordering, not privileged truncation."""

    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path).expanduser() if path is not None else None
        self._lock = threading.RLock()
        self._entries: list[dict[str, object]] = []
        if self.path is not None:
            self._load_and_verify()

    @staticmethod
    def _digest(payload: dict[str, object]) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _load_and_verify(self) -> None:
        assert self.path is not None
        previous_count = len(self._entries)
        if self.path.is_symlink():
            raise AuditLogIntegrityError("audit log path must not be a symbolic link")
        if not self.path.exists():
            if previous_count:
                raise AuditLogIntegrityError("audit log disappeared after it was initialized")
            return
        try:
            raw_lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise AuditLogIntegrityError(f"cannot read audit log: {exc}") from exc
        if len(raw_lines) < previous_count:
            raise AuditLogIntegrityError("audit log was truncated after it was initialized")
        previous = ZERO_HASH
        verified: list[dict[str, object]] = []
        for expected_sequence, line in enumerate(raw_lines, start=1):
            try:
                item = json.loads(line)
                if not isinstance(item, dict) or set(item) != {
                    "sequence", "timestamp", "previous_hash", "event", "hash"
                }:
                    raise ValueError("unexpected entry shape")
                if item["sequence"] != expected_sequence or item["previous_hash"] != previous:
                    raise ValueError("sequence or previous hash mismatch")
                if not isinstance(item["event"], dict) or not isinstance(item["timestamp"], str):
                    raise ValueError("invalid event or timestamp")
                claimed_hash = item["hash"]
                payload = {key: value for key, value in item.items() if key != "hash"}
                if not isinstance(claimed_hash, str) or not secrets.compare_digest(
                    claimed_hash, self._digest(payload)
                ):
                    raise ValueError("entry hash mismatch")
                parsed_timestamp = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
                _require_aware(parsed_timestamp, "audit timestamp")
            except (ValueError, TypeError, KeyError) as exc:
                raise AuditLogIntegrityError(
                    f"audit log integrity check failed at line {expected_sequence}: {exc}"
                ) from exc
            verified.append(item)
            previous = claimed_hash
        self._entries = verified

    def append(self, event: dict[str, object], timestamp: datetime) -> int:
        with self._lock:
            if self.path is not None:
                # Recheck disk state before every decision. One process should own a
                # given log; concurrent independent writers are intentionally unsupported.
                self._load_and_verify()
            previous = str(self._entries[-1]["hash"]) if self._entries else ZERO_HASH
            payload: dict[str, object] = {
                "sequence": len(self._entries) + 1,
                "timestamp": _utc_iso(timestamp),
                "previous_hash": previous,
                "event": event,
            }
            entry = {**payload, "hash": self._digest(payload)}
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.is_symlink():
                    raise AuditLogIntegrityError("audit log path must not be a symbolic link")
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
                flags |= getattr(os, "O_NOFOLLOW", 0)
                try:
                    descriptor = os.open(self.path, flags, 0o600)
                    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                        handle.write(line)
                        handle.flush()
                        os.fsync(handle.fileno())
                except OSError as exc:
                    raise AuditLogIntegrityError(f"cannot append audit log: {exc}") from exc
            self._entries.append(entry)
            return int(entry["sequence"])

    def entries(self) -> list[dict[str, object]]:
        with self._lock:
            return copy.deepcopy(self._entries)


class AuthorityKernel:
    """Authorize explicit capabilities against exact-resource, expiring grants.

    Mutating capabilities additionally require an exact-match, expiring,
    single-use approval token. The host application is responsible for
    authenticating the human approver before requesting such a token.
    """

    def __init__(
        self,
        capabilities: Iterable[CapabilitySpec],
        grants: Iterable[Grant] = (),
        *,
        audit_path: str | Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        specs: dict[str, CapabilitySpec] = {}
        for spec in capabilities:
            if not isinstance(spec, CapabilitySpec):
                raise TypeError("capabilities must contain CapabilitySpec values")
            if spec.name in specs:
                raise ValueError(f"duplicate capability: {spec.name}")
            specs[spec.name] = spec
        self._capabilities = specs
        self._grants = tuple(grants)
        for grant in self._grants:
            if not isinstance(grant, Grant):
                raise TypeError("grants must contain Grant values")
            if grant.capability not in specs:
                raise ValueError(f"grant references an unknown capability: {grant.capability}")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        _require_aware(self._clock(), "clock result")
        self._approvals: dict[str, _Approval] = {}
        self._lock = threading.RLock()
        self._audit = _AuditTrail(audit_path)

    @classmethod
    def from_policy_file(
        cls,
        capabilities: Iterable[CapabilitySpec],
        policy_path: str | Path,
        *,
        audit_path: str | Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> "AuthorityKernel":
        capability_specs = tuple(capabilities)
        path = Path(policy_path).expanduser()
        if path.is_symlink():
            raise AuthorityError("policy file must not be a symbolic link")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AuthorityError(f"cannot read policy file: {exc}") from exc
        if (not isinstance(payload, dict) or set(payload) != {"version", "grants"}
                or type(payload["version"]) is not int or payload["version"] != 1):
            raise AuthorityError("policy must contain only version=1 and grants")
        if not isinstance(payload["grants"], list):
            raise AuthorityError("policy grants must be a list")
        capability_names = {spec.name for spec in capability_specs}
        grants: list[Grant] = []
        for index, item in enumerate(payload["grants"]):
            if not isinstance(item, dict) or set(item) != {
                "subject", "capability", "resource", "expires_at"
            }:
                raise AuthorityError(f"policy grant {index} has an invalid shape")
            try:
                expires = datetime.fromisoformat(str(item["expires_at"]).replace("Z", "+00:00"))
                grant = Grant(
                    subject=item["subject"],
                    capability=item["capability"],
                    resource=item["resource"],
                    expires_at=expires,
                )
                if grant.capability not in capability_names:
                    raise ValueError(f"unknown capability: {grant.capability}")
                grants.append(grant)
            except (TypeError, ValueError) as exc:
                raise AuthorityError(f"policy grant {index} is invalid: {exc}") from exc
        return cls(capability_specs, grants, audit_path=audit_path, clock=clock)

    def _now(self) -> datetime:
        value = self._clock()
        _require_aware(value, "clock result")
        return value.astimezone(timezone.utc)

    def _has_active_grant(self, subject: str, capability: str, resource: str, now: datetime) -> bool:
        return any(
            grant.subject == subject
            and grant.capability == capability
            and grant.resource == resource
            and grant.expires_at.astimezone(timezone.utc) > now
            for grant in self._grants
        )

    def _prune_expired_approvals(
        self,
        now: datetime,
        *,
        preserve_token: str | None = None,
    ) -> None:
        """Discard expired tokens, except one being checked for an audit reason."""
        expired = [
            token
            for token, approval in self._approvals.items()
            if token != preserve_token and approval.expires_at <= now
        ]
        for token in expired:
            self._approvals.pop(token, None)

    def issue_approval(
        self,
        *,
        subject: str,
        capability: str,
        resource: str,
        approver: str,
        ttl_seconds: int = 300,
    ) -> str:
        """Issue a one-time mutation approval after host-authenticated consent.

        This method is not an authentication mechanism. Never expose it directly
        to an unauthenticated client or call it before a human approval event.
        """
        _validate_label(subject, "subject", 256)
        _validate_label(resource, "resource", 1024)
        _validate_label(approver, "approver", 256)
        spec = self._capabilities.get(capability)
        if spec is None or not spec.mutates:
            raise AuthorityError("one-time approvals are only available for known mutating capabilities")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= MAX_APPROVAL_TTL_SECONDS:
            raise ValueError(f"approval TTL must be between 1 and {MAX_APPROVAL_TTL_SECONDS} seconds")
        with self._lock:
            now = self._now()
            self._prune_expired_approvals(now)
            if not self._has_active_grant(subject, capability, resource, now):
                raise AuthorityError("cannot approve an operation without an active exact-scope grant")
            if len(self._approvals) >= MAX_OUTSTANDING_APPROVALS:
                raise AuthorityError("too many outstanding approvals; retry after existing approvals expire")
            token = secrets.token_urlsafe(32)
            self._audit.append({
                "type": "approval_issued",
                "subject": subject,
                "capability": capability,
                "resource": resource,
                "approver": approver,
                "expires_at": _utc_iso(now + timedelta(seconds=ttl_seconds)),
            }, now)
            self._approvals[token] = _Approval(
                subject, capability, resource, approver, now + timedelta(seconds=ttl_seconds)
            )
            return token

    def authorize(
        self,
        *,
        subject: str,
        capability: str,
        resource: str,
        approval_token: str | None = None,
    ) -> Decision:
        """Record and return an authorization decision; never execute the action."""
        _validate_label(subject, "subject", 256)
        _validate_label(resource, "resource", 1024)
        if not isinstance(capability, str) or not CAPABILITY_RE.fullmatch(capability):
            raise ValueError("capability must be a dotted lowercase identifier")
        with self._lock:
            now = self._now()
            self._prune_expired_approvals(now, preserve_token=approval_token)
            spec = self._capabilities.get(capability)
            reason = "unknown_capability"
            allowed = False
            matched_token: str | None = None
            if spec is not None:
                if not self._has_active_grant(subject, capability, resource, now):
                    reason = "no_active_exact_scope_grant"
                elif spec.mutates:
                    reason = "approval_required"
                    if isinstance(approval_token, str) and approval_token:
                        approval = self._approvals.get(approval_token)
                        if approval is not None:
                            if (
                                approval.subject == subject
                                and approval.capability == capability
                                and approval.resource == resource
                                and approval.expires_at > now
                            ):
                                allowed = True
                                reason = "authorized_single_use_approval"
                                matched_token = approval_token
                            elif approval.expires_at <= now:
                                self._approvals.pop(approval_token, None)
                                reason = "approval_expired"
                            else:
                                reason = "approval_scope_mismatch"
                        else:
                            reason = "invalid_or_consumed_approval"
                else:
                    allowed = True
                    reason = "authorized_active_grant"

            if matched_token is not None:
                self._approvals.pop(matched_token, None)
            sequence = self._audit.append({
                "type": "authorization_decision",
                "subject": subject,
                "capability": capability,
                "resource": resource,
                "allowed": allowed,
                "reason": reason,
            }, now)
            return Decision(allowed, subject, capability, resource, reason, sequence)

    def record_execution_started(
        self,
        *,
        decision: Decision,
        execution_id: str,
        adapter_id: str,
        operation: str,
    ) -> int:
        """Record that a handler is about to run for a verified allow decision.

        This must be called after authorization and before invoking the handler.
        If the audit append fails, the handler must not be invoked.
        """
        if not isinstance(decision, Decision) or not decision.allowed:
            raise AuthorityError("execution can only start from an allowed authorization decision")
        _validate_label(execution_id, "execution_id", 128)
        _validate_label(adapter_id, "adapter_id", 64)
        _validate_label(operation, "operation", 64)
        with self._lock:
            entries = self._audit.entries()
            sequence = decision.audit_sequence
            if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence <= len(entries):
                raise AuthorityError("authorization decision sequence is not present in the audit log")
            event = entries[sequence - 1].get("event")
            if not isinstance(event, dict) or event != {
                "type": "authorization_decision",
                "subject": decision.subject,
                "capability": decision.capability,
                "resource": decision.resource,
                "allowed": True,
                "reason": decision.reason,
            }:
                raise AuthorityError("execution start does not match a verified allowed decision")
            if any(
                isinstance(item.get("event"), dict)
                and item["event"].get("execution_id") == execution_id
                for item in entries
            ):
                raise AuthorityError("execution_id has already been used")
            if any(
                isinstance(item.get("event"), dict)
                and item["event"].get("type") == "execution_started"
                and item["event"].get("authorization_sequence") == sequence
                for item in entries
            ):
                raise AuthorityError("authorization decision has already started an execution")
            now = self._now()
            return self._audit.append({
                "type": "execution_started",
                "execution_id": execution_id,
                "authorization_sequence": sequence,
                "subject": decision.subject,
                "capability": decision.capability,
                "resource": decision.resource,
                "adapter_id": adapter_id,
                "operation": operation,
            }, now)

    def record_execution_result(
        self,
        *,
        start_sequence: int,
        execution_id: str,
        outcome: str,
        duration_ms: int,
        error_type: str | None = None,
    ) -> int:
        """Record a handler outcome against one prior execution-start event.

        Error messages and operation results are intentionally excluded because
        they may contain secrets or untrusted data.
        """
        _validate_label(execution_id, "execution_id", 128)
        if not isinstance(outcome, str) or outcome not in {"succeeded", "failed", "timed_out"}:
            raise ValueError("execution outcome must be 'succeeded', 'failed', or 'timed_out'")
        if isinstance(start_sequence, bool) or not isinstance(start_sequence, int) or start_sequence < 1:
            raise ValueError("start_sequence must be a positive integer")
        if (
            isinstance(duration_ms, bool)
            or not isinstance(duration_ms, int)
            or not 0 <= duration_ms <= (1 << 63) - 1
        ):
            raise ValueError("duration_ms must be a non-negative signed 64-bit integer")
        if outcome in {"failed", "timed_out"}:
            _validate_label(error_type, "error_type", 256)
        elif error_type is not None:
            raise ValueError("successful execution cannot include an error_type")
        with self._lock:
            entries = self._audit.entries()
            if start_sequence > len(entries):
                raise AuthorityError("execution start sequence is not present in the audit log")
            start_event = entries[start_sequence - 1].get("event")
            if (
                not isinstance(start_event, dict)
                or start_event.get("type") != "execution_started"
                or start_event.get("execution_id") != execution_id
            ):
                raise AuthorityError("execution result does not match its start event")
            if any(
                isinstance(item.get("event"), dict)
                and item["event"].get("type") == "execution_result"
                and item["event"].get("start_sequence") == start_sequence
                for item in entries
            ):
                raise AuthorityError("execution result has already been recorded")
            now = self._now()
            return self._audit.append({
                "type": "execution_result",
                "execution_id": execution_id,
                "start_sequence": start_sequence,
                "authorization_sequence": start_event["authorization_sequence"],
                "subject": start_event["subject"],
                "capability": start_event["capability"],
                "resource": start_event["resource"],
                "adapter_id": start_event["adapter_id"],
                "operation": start_event["operation"],
                "outcome": outcome,
                "duration_ms": duration_ms,
                "error_type": error_type,
            }, now)

    def capability_is_mutating(self, capability: str) -> bool | None:
        """Return a capability's mutation classification, or None when unknown."""
        spec = self._capabilities.get(capability)
        return spec.mutates if spec is not None else None

    def audit_entries(self) -> list[dict[str, object]]:
        """Return a copy of verified decision-log entries."""
        return self._audit.entries()


DEFAULT_CAPABILITIES = (
    CapabilitySpec("project.inspect", "Read and analyze an explicitly scoped project."),
    CapabilitySpec("project.repair", "Modify an explicitly scoped project after approval.", mutates=True),
    CapabilitySpec("service.inspect", "Read status from an explicitly connected service."),
    CapabilitySpec("service.restart", "Restart an explicitly connected service after approval.", mutates=True),
    CapabilitySpec("device.inspect", "Read status from an explicitly paired device."),
    CapabilitySpec("device.control", "Send an explicitly approved command to a paired device.", mutates=True),
)

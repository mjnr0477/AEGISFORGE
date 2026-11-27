import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegisforge.authority import (
    AuditLogIntegrityError,
    AuthorityError,
    AuthorityKernel,
    CapabilitySpec,
    Grant,
)


class AuthorityKernelTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
        self.clock = lambda: self.now
        self.capabilities = (
            CapabilitySpec("project.inspect", "Read project"),
            CapabilitySpec("project.repair", "Modify project", mutates=True),
        )
        self.grants = (
            Grant("operator", "project.inspect", "project:/repo-a", self.now + timedelta(hours=1)),
            Grant("operator", "project.repair", "project:/repo-a", self.now + timedelta(hours=1)),
        )

    def make_kernel(self, **kwargs):
        return AuthorityKernel(self.capabilities, self.grants, clock=self.clock, **kwargs)

    def test_default_deny_for_unknown_capability(self):
        decision = self.make_kernel().authorize(
            subject="operator", capability="project.delete", resource="project:/repo-a"
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "unknown_capability")

    def test_grant_must_match_subject_capability_and_exact_resource(self):
        kernel = self.make_kernel()
        for subject, capability, resource in (
            ("guest", "project.inspect", "project:/repo-a"),
            ("operator", "project.inspect", "project:/repo-b"),
            ("operator", "project.repair", "project:/repo-b"),
        ):
            decision = kernel.authorize(subject=subject, capability=capability, resource=resource)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "no_active_exact_scope_grant")

    def test_read_only_grant_authorizes_without_approval(self):
        decision = self.make_kernel().authorize(
            subject="operator", capability="project.inspect", resource="project:/repo-a"
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "authorized_active_grant")

    def test_mutation_requires_approval(self):
        decision = self.make_kernel().authorize(
            subject="operator", capability="project.repair", resource="project:/repo-a"
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "approval_required")

    def test_mutation_approval_is_exact_scope_and_single_use(self):
        kernel = self.make_kernel()
        token = kernel.issue_approval(
            subject="operator", capability="project.repair", resource="project:/repo-a", approver="owner"
        )
        mismatch = kernel.authorize(
            subject="operator", capability="project.repair", resource="project:/repo-b", approval_token=token
        )
        self.assertFalse(mismatch.allowed)
        self.assertEqual(mismatch.reason, "no_active_exact_scope_grant")
        allowed = kernel.authorize(
            subject="operator", capability="project.repair", resource="project:/repo-a", approval_token=token
        )
        self.assertTrue(allowed.allowed)
        reused = kernel.authorize(
            subject="operator", capability="project.repair", resource="project:/repo-a", approval_token=token
        )
        self.assertFalse(reused.allowed)
        self.assertEqual(reused.reason, "invalid_or_consumed_approval")

    def test_approval_requires_active_grant_and_mutating_capability(self):
        kernel = self.make_kernel()
        with self.assertRaises(AuthorityError):
            kernel.issue_approval(
                subject="guest", capability="project.repair", resource="project:/repo-a", approver="owner"
            )
        with self.assertRaises(AuthorityError):
            kernel.issue_approval(
                subject="operator", capability="project.inspect", resource="project:/repo-a", approver="owner"
            )

    def test_expired_grants_and_approvals_are_denied(self):
        expired_grant = Grant("operator", "project.inspect", "project:/repo-a", self.now)
        kernel = AuthorityKernel(self.capabilities, (expired_grant,), clock=self.clock)
        denied = kernel.authorize(
            subject="operator", capability="project.inspect", resource="project:/repo-a"
        )
        self.assertFalse(denied.allowed)

        kernel = self.make_kernel()
        token = kernel.issue_approval(
            subject="operator", capability="project.repair", resource="project:/repo-a", approver="owner", ttl_seconds=1
        )
        self.now += timedelta(seconds=2)
        expired = kernel.authorize(
            subject="operator", capability="project.repair", resource="project:/repo-a", approval_token=token
        )
        self.assertFalse(expired.allowed)
        self.assertEqual(expired.reason, "approval_expired")

    def test_audit_log_is_hash_chained_and_reloaded(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "audit.jsonl"
            kernel = self.make_kernel(audit_path=path)
            kernel.authorize(subject="operator", capability="project.inspect", resource="project:/repo-a")
            kernel.authorize(subject="guest", capability="project.inspect", resource="project:/repo-a")
            reloaded = self.make_kernel(audit_path=path)
            entries = reloaded.audit_entries()
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[1]["previous_hash"], entries[0]["hash"])

    def test_audit_log_modification_is_detected_on_reload_and_before_next_decision(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "audit.jsonl"
            kernel = self.make_kernel(audit_path=path)
            kernel.authorize(subject="operator", capability="project.inspect", resource="project:/repo-a")
            text = path.read_text(encoding="utf-8").replace("authorized_active_grant", "forged_active_grant")
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(AuditLogIntegrityError):
                kernel.authorize(subject="operator", capability="project.inspect", resource="project:/repo-a")
            with self.assertRaises(AuditLogIntegrityError):
                self.make_kernel(audit_path=path)

    def test_audit_entries_are_returned_as_defensive_copies(self):
        kernel = self.make_kernel()
        kernel.authorize(subject="operator", capability="project.inspect", resource="project:/repo-a")
        view = kernel.audit_entries()
        view[0]["event"]["allowed"] = False
        self.assertTrue(kernel.audit_entries()[0]["event"]["allowed"])

    def test_audit_log_truncation_is_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "audit.jsonl"
            kernel = self.make_kernel(audit_path=path)
            kernel.authorize(subject="operator", capability="project.inspect", resource="project:/repo-a")
            path.write_text("", encoding="utf-8")
            with self.assertRaises(AuditLogIntegrityError):
                kernel.authorize(subject="operator", capability="project.inspect", resource="project:/repo-a")

    def test_policy_file_loads_exact_expiring_grants(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps({
                "version": 1,
                "grants": [{
                    "subject": "operator",
                    "capability": "project.inspect",
                    "resource": "project:/repo-a",
                    "expires_at": (self.now + timedelta(hours=1)).isoformat(),
                }],
            }), encoding="utf-8")
            kernel = AuthorityKernel.from_policy_file(self.capabilities, path, clock=self.clock)
            decision = kernel.authorize(
                subject="operator", capability="project.inspect", resource="project:/repo-a"
            )
            self.assertTrue(decision.allowed)

    def test_policy_rejects_unknown_fields_version_and_capabilities(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text('{"version": 2, "grants": [], "allow_all": true}', encoding="utf-8")
            with self.assertRaises(AuthorityError):
                AuthorityKernel.from_policy_file(self.capabilities, path)
            path.write_text('{"version": true, "grants": []}', encoding="utf-8")
            with self.assertRaises(AuthorityError):
                AuthorityKernel.from_policy_file(self.capabilities, path)
            path.write_text(json.dumps({
                "version": 1,
                "grants": [{
                    "subject": "operator",
                    "capability": "project.delete",
                    "resource": "project:/repo-a",
                    "expires_at": (self.now + timedelta(hours=1)).isoformat(),
                }],
            }), encoding="utf-8")
            with self.assertRaises(AuthorityError):
                AuthorityKernel.from_policy_file(self.capabilities, path)

    def test_audit_failure_blocks_authorization(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "audit.jsonl"
            kernel = self.make_kernel(audit_path=path)
            path.mkdir()
            with self.assertRaises(AuditLogIntegrityError):
                kernel.authorize(subject="operator", capability="project.inspect", resource="project:/repo-a")

    def test_input_validation_rejects_control_characters_and_naive_dates(self):
        with self.assertRaises(ValueError):
            Grant("operator\nroot", "project.inspect", "project:/repo-a", self.now)
        with self.assertRaises(ValueError):
            Grant("operator", "project.inspect", "project:/repo-a", datetime(2026, 1, 1))


if __name__ == "__main__":
    unittest.main()

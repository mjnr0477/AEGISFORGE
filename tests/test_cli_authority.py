import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegisforge.cli import main
from aegisforge.authority import AuthorityKernel, DEFAULT_CAPABILITIES, Grant


class AuthorityCLITests(unittest.TestCase):
    def test_authority_check_allows_scoped_read_only_capability_and_writes_log(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "version": 1,
                "grants": [{
                    "subject": "operator",
                    "capability": "project.inspect",
                    "resource": "project:/repo-a",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                }],
            }), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main([
                    "authority", "check", "--policy", str(policy),
                    "--audit-log", str(root / "authority.jsonl"),
                    "--subject", "operator", "--capability", "project.inspect",
                    "--resource", "project:/repo-a", "--format", "json",
                ])
            self.assertEqual(result, 0)
            self.assertTrue(json.loads(output.getvalue())["allowed"])
            self.assertTrue((root / "authority.jsonl").is_file())


    def _write_execution_ledger(self, path, *, complete):
        now = datetime.now(timezone.utc)
        kernel = AuthorityKernel(
            DEFAULT_CAPABILITIES,
            [Grant("operator", "project.inspect", "project:/repo-a", now + timedelta(hours=1))],
            audit_path=path,
            clock=lambda: now,
        )
        decision = kernel.authorize(
            subject="operator", capability="project.inspect", resource="project:/repo-a"
        )
        start_sequence = kernel.record_execution_started(
            decision=decision,
            execution_id="cli-audit-execution-1",
            adapter_id="local-tool-registry",
            operation="scan_project",
        )
        if complete:
            kernel.record_execution_result(
                start_sequence=start_sequence,
                execution_id="cli-audit-execution-1",
                outcome="succeeded",
                duration_ms=12,
            )

    def test_authority_audit_verifies_ledger_and_reports_completed_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "authority.jsonl"
            self._write_execution_ledger(path, complete=True)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["authority", "audit", "--audit-log", str(path), "--format", "json"])
            payload = json.loads(output.getvalue())
            self.assertEqual(result, 0)
            self.assertTrue(payload["verified"])
            self.assertEqual(payload["entry_count"], 3)
            self.assertEqual(payload["pending_count"], 0)
            self.assertEqual(payload["entries"][-1]["event"]["outcome"], "succeeded")

    def test_authority_audit_reports_unknown_outcome_without_retrying(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "authority.jsonl"
            self._write_execution_ledger(path, complete=False)
            ledger_before = path.read_bytes()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["authority", "audit", "--audit-log", str(path)])
            self.assertEqual(result, 0)
            self.assertEqual(path.read_bytes(), ledger_before)
            self.assertIn("Authority audit ledger: VERIFIED", output.getvalue())
            self.assertIn("OUTCOME UNKNOWN", output.getvalue())
            self.assertIn("Reconcile unknown outcomes before retrying", output.getvalue())

    def test_authority_audit_rejects_missing_and_tampered_logs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            missing_output = io.StringIO()
            with contextlib.redirect_stderr(missing_output):
                missing_result = main(["authority", "audit", "--audit-log", str(root / "missing.jsonl")])
            self.assertEqual(missing_result, 2)
            self.assertIn("does not exist", missing_output.getvalue())

            path = root / "tampered.jsonl"
            self._write_execution_ledger(path, complete=True)
            contents = path.read_text(encoding="utf-8")
            path.write_text(contents.replace('"reason":"authorized_active_grant"', '"reason":"forged_grant"'), encoding="utf-8")
            error_output = io.StringIO()
            with contextlib.redirect_stderr(error_output):
                tampered_result = main(["authority", "audit", "--audit-log", str(path)])
            self.assertEqual(tampered_result, 2)
            self.assertIn("integrity check failed", error_output.getvalue())

    def test_authority_check_denies_mutation_without_one_time_approval(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "version": 1,
                "grants": [{
                    "subject": "operator",
                    "capability": "project.repair",
                    "resource": "project:/repo-a",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                }],
            }), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main([
                    "authority", "check", "--policy", str(policy),
                    "--audit-log", str(root / "authority.jsonl"),
                    "--subject", "operator", "--capability", "project.repair",
                    "--resource", "project:/repo-a",
                ])
            self.assertEqual(result, 1)
            self.assertIn("approval_required", output.getvalue())


if __name__ == "__main__":
    unittest.main()

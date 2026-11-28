import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegisforge.authority import AuthorityKernel, DEFAULT_CAPABILITIES, Grant
from aegisforge.cli import main

class CLITests(unittest.TestCase):
    def test_authority_audit_json_reports_pending_execution_without_writing(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "authority.jsonl"
            now = datetime.now(timezone.utc)
            kernel = AuthorityKernel(
                DEFAULT_CAPABILITIES,
                grants=[
                    Grant(
                        "operator",
                        "project.inspect",
                        "project:/repo-a",
                        now + timedelta(hours=1),
                    )
                ],
                audit_path=path,
            )
            decision = kernel.authorize(
                subject="operator",
                capability="project.inspect",
                resource="project:/repo-a",
            )
            kernel.record_execution_started(
                decision=decision,
                execution_id="execution-cli-pending-0001",
                adapter_id="demo-adapter",
                operation="inspect",
            )
            before = path.read_bytes()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main([
                    "authority", "audit", "--audit-log", str(path), "--format", "json"
                ])

            payload = json.loads(output.getvalue())
            self.assertEqual(result, 0)
            self.assertTrue(payload["verified"])
            self.assertEqual(payload["entry_count"], 2)
            self.assertEqual(payload["pending_count"], 1)
            self.assertEqual(
                payload["pending_executions"][0]["status"], "outcome_unknown"
            )
            self.assertEqual(path.read_bytes(), before)

    def test_authority_audit_refuses_tampered_and_missing_ledgers(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "authority.jsonl"
            kernel = AuthorityKernel(DEFAULT_CAPABILITIES, audit_path=path)
            kernel.authorize(
                subject="guest",
                capability="project.inspect",
                resource="project:/repo-a",
            )
            forged = path.read_text(encoding="utf-8").replace(
                "no_active_exact_scope_grant", "forged_exact_scope_grant"
            )
            path.write_text(forged, encoding="utf-8")

            output = io.StringIO()
            errors = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                result = main([
                    "authority", "audit", "--audit-log", str(path), "--format", "json"
                ])
            self.assertEqual(result, 2)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("integrity check failed", errors.getvalue())

            output = io.StringIO()
            errors = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                result = main([
                    "authority", "audit", "--audit-log", str(Path(folder) / "missing.jsonl")
                ])
            self.assertEqual(result, 2)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("does not exist", errors.getvalue())

    def test_rules_command_lists_checks(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["rules"])
        self.assertEqual(result, 0)
        self.assertIn("AF-PY-001", output.getvalue())

    def test_scan_returns_one_for_high_severity(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "app.py").write_text("eval(user_input)\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["scan", folder, "--format", "json"])
            self.assertEqual(result, 1)
            self.assertIn("AF-PY-001", output.getvalue())

    def test_scan_empty_directory_returns_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["scan", folder, "--format", "text"])
            self.assertEqual(result, 0)

if __name__ == "__main__":
    unittest.main()

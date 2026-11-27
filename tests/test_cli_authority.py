import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegisforge.cli import main


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

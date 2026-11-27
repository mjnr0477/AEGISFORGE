import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aegisforge.cli import main

class MissionCLITests(unittest.TestCase):
    def test_tools_command_lists_safe_local_tools(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            status=main(["tools","--format","json"])
        self.assertEqual(status,0)
        catalog=json.loads(output.getvalue())
        by_name={tool["name"]:tool for tool in catalog}
        self.assertIn("scan_project",by_name)
        self.assertFalse(by_name["scan_project"]["mutates"])
        self.assertTrue(by_name["apply_supported_repairs"]["mutates"])

    def test_mission_preview_does_not_modify_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source=root/"settings.env"
            source.write_text("DEBUG=true\n",encoding="utf-8")
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                status=main(["mission","audit",str(root),"--format","json"])
            payload=json.loads(output.getvalue())
            self.assertEqual(status,0)
            self.assertEqual(payload["status"],"approval_required")
            self.assertEqual(source.read_text(encoding="utf-8"),"DEBUG=true\n")

    def test_mission_apply_flag_runs_verified_repair(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source=root/"settings.env"
            source.write_text("DEBUG=true\n",encoding="utf-8")
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                status=main(["mission","audit",str(root),"--apply-supported-repairs","--format","json"])
            payload=json.loads(output.getvalue())
            self.assertEqual(status,0)
            self.assertEqual(payload["status"],"completed")
            self.assertEqual(source.read_text(encoding="utf-8"),"DEBUG=false\n")
            self.assertEqual(len(payload["applied_backups"]),1)

    def test_mission_text_reports_circular_import_group_count(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"alpha.py").write_text("import beta\n",encoding="utf-8")
            (root/"beta.py").write_text("import alpha\n",encoding="utf-8")
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                status=main(["mission","audit",str(root)])
        self.assertEqual(status,0)
        self.assertIn("1 circular import groups",output.getvalue())

    def test_mission_incomplete_scan_returns_operational_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"too-large.py").write_bytes(b"x"*(1_000_001))
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                status=main(["mission","audit",str(root),"--format","json"])
            payload=json.loads(output.getvalue())
            self.assertEqual(status,2)
            self.assertEqual(payload["status"],"incomplete")

if __name__ == "__main__":
    unittest.main()

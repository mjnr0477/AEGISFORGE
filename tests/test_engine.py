import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from aegisforge.engine import load_plan_file, run_trial, validate_plan


def make_plan(path: str, original: str, replacement: str) -> dict:
    return {
        "schema_version": 1,
        "changes": [{
            "path": path,
            "expected_sha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
            "replacement": replacement,
        }],
    }


class ControlledTrialTests(unittest.TestCase):
    def test_accepts_fix_in_temporary_copy_and_leaves_source_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "app.py"
            original = "eval(user_input)\n"
            source.write_text(original, encoding="utf-8")

            report = run_trial(root, make_plan("app.py", original, "result = user_input\n"))

            self.assertEqual(report["decision"], "accepted")
            self.assertEqual(report["resolved_findings"][0]["rule_id"], "AF-PY-001")
            self.assertFalse(report["execution"]["project_code_executed"])
            self.assertFalse(report["execution"]["source_project_modified"])
            self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_rejects_new_high_severity_finding_without_modifying_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "app.py"
            original = "value = 1\n"
            source.write_text(original, encoding="utf-8")

            report = run_trial(root, make_plan("app.py", original, "eval(user_input)\n"))

            self.assertEqual(report["decision"], "rejected")
            self.assertEqual(report["introduced_findings"][0]["rule_id"], "AF-PY-001")
            self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_marks_new_low_severity_finding_for_review(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "crypto.py"
            original = "value = 1\n"
            source.write_text(original, encoding="utf-8")
            replacement = "import hashlib\nvalue = hashlib.md5(b'x')\n"

            report = run_trial(root, make_plan("crypto.py", original, replacement))

            self.assertEqual(report["decision"], "review")
            self.assertEqual(report["introduced_findings"][0]["rule_id"], "AF-PY-006")

    def test_rejects_stale_plan(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "app.py"
            source.write_text("value = 1\n", encoding="utf-8")
            plan = make_plan("app.py", "value = 1\n", "value = 2\n")
            source.write_text("value = 3\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "stale change plan"):
                run_trial(root, plan)

    def test_rejects_traversal_and_duplicate_paths(self):
        with self.assertRaisesRegex(ValueError, "unsafe change path"):
            validate_plan(make_plan("../outside.py", "x = 1\n", "x = 2\n"))
        plan = {
            "schema_version": 1,
            "changes": [
                {"path": "app.py", "expected_sha256": "0" * 64, "replacement": "x = 1"},
                {"path": "app.py", "expected_sha256": "0" * 64, "replacement": "x = 2"},
            ],
        }
        with self.assertRaisesRegex(ValueError, "duplicate change path"):
            validate_plan(plan)

    def test_rejects_unknown_fields_that_could_smuggle_commands(self):
        plan = make_plan("app.py", "x = 1\n", "x = 2\n")
        plan["commands"] = ["python app.py"]
        with self.assertRaisesRegex(ValueError, "only schema_version and changes"):
            validate_plan(plan)

    def test_plan_file_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "plan.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1,"changes":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
                load_plan_file(path)

    def test_candidate_project_code_is_never_executed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            marker = root / "must-not-exist.txt"
            source = root / "app.py"
            original = "value = 1\n"
            source.write_text(original, encoding="utf-8")
            replacement = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
                "eval(user_input)\n"
            )

            report = run_trial(root, make_plan("app.py", original, replacement))

            self.assertEqual(report["decision"], "rejected")
            self.assertFalse(marker.exists())
            self.assertEqual(source.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()

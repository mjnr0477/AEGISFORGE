import json
import tempfile
import unittest
from pathlib import Path

from aegisforge.baselines import compare_with_baseline, create_baseline, load_baseline
from aegisforge.models import Finding, ScanResult

class BaselineTests(unittest.TestCase):
    def _finding(self, rule_id="AF-PY-001", path="app.py", line=3):
        return Finding(rule_id, "high", "Dynamic code evaluation",
            "Dynamic evaluation may execute untrusted code.", path, line, 1,
            "eval(user_input)", "Avoid dynamic evaluation.", "high", "CWE-95")

    def test_create_and_load_baseline_round_trip(self):
        result = ScanResult("/private/work/project", 1, 0, [self._finding()], [])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "baseline.json"
            payload = create_baseline(result, path)
            loaded = load_baseline(path)
            serialized = path.read_text(encoding="utf-8")
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(loaded["findings"][0]["path"], "app.py")
        self.assertNotIn("/private/work", serialized)

    def test_compare_classifies_new_known_and_resolved_findings(self):
        old = ScanResult("/project", 2, 0, [self._finding(), self._finding("AF-PY-002", "db.py", 8)], [])
        new = ScanResult("/project", 2, 0, [self._finding(), self._finding("AF-PY-003", "api.py", 12)], [])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "baseline.json"
            create_baseline(old, path)
            comparison = compare_with_baseline(new, load_baseline(path))
        self.assertEqual([item.rule_id for item in comparison["known"]], ["AF-PY-001"])
        self.assertEqual([item.rule_id for item in comparison["new"]], ["AF-PY-003"])
        self.assertEqual([item.rule_id for item in comparison["resolved"]], ["AF-PY-002"])

    def test_rejects_tampered_baseline_fingerprint(self):
        result = ScanResult("/project", 1, 0, [self._finding()], [])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "baseline.json"
            create_baseline(result, path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["findings"][0]["fingerprint"] = "0" * 64
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                load_baseline(path)

    def test_rejects_absolute_and_traversal_paths_in_baseline(self):
        result = ScanResult("/project", 1, 0, [self._finding()], [])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "baseline.json"
            create_baseline(result, path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["findings"][0]["path"] = "../../outside.py"
            from aegisforge.baselines import finding_fingerprint
            data = {key:value for key,value in payload["findings"][0].items() if key != "fingerprint"}
            payload["findings"][0]["fingerprint"] = finding_fingerprint(Finding(**data))
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "safe relative path"):
                load_baseline(path)

    def test_refuses_to_write_a_baseline_over_the_size_limit(self):
        from unittest.mock import patch
        import aegisforge.baselines as module
        result = ScanResult("/project", 1, 0, [self._finding()], [])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "baseline.json"
            with patch.object(module, "MAX_BASELINE_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "write limit"):
                    create_baseline(result, path)
            self.assertFalse(path.exists())

    def test_rejects_unknown_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "baseline.json"
            path.write_text(json.dumps({"schema_version":99,"findings":[]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schema"):
                load_baseline(path)

if __name__ == "__main__":
    unittest.main()

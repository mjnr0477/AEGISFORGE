import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

class BaselineCLITests(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "aegisforge", *args], capture_output=True, text=True)

    def test_create_and_compare_baseline_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"project"
            root.mkdir()
            source=root/"app.py"
            source.write_text("eval(user_input)\n",encoding="utf-8")
            baseline=Path(temp)/"baseline.json"

            created=self._run("baseline","create",str(root),"--output",str(baseline))
            self.assertEqual(created.returncode,0,created.stderr)
            self.assertTrue(baseline.exists())

            source.write_text("print('safe')\n",encoding="utf-8")
            compared=self._run("baseline","compare",str(root),"--input",str(baseline),"--format","json")
            self.assertEqual(compared.returncode,0,compared.stderr)
            report=json.loads(compared.stdout)
            self.assertEqual(len(report["resolved"]),1)
            self.assertEqual(report["resolved"][0]["rule_id"],"AF-PY-001")
            self.assertEqual(report["new"],[])

    def test_incomplete_scan_does_not_create_default_baseline(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"project"
            root.mkdir()
            (root/"too-large.py").write_bytes(b"x" * 1_000_001)
            result=self._run("baseline","create",str(root))
            self.assertEqual(result.returncode,2)
            self.assertFalse((root/".aegisforge"/"baseline.json").exists())

    def test_invalid_baseline_returns_operational_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"project"
            root.mkdir()
            baseline=Path(temp)/"invalid.json"
            baseline.write_text("{broken",encoding="utf-8")
            result=self._run("baseline","compare",str(root),"--input",str(baseline))
            self.assertEqual(result.returncode,2)
            self.assertIn("cannot read baseline",result.stderr)

if __name__ == "__main__":
    unittest.main()

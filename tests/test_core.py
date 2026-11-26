import json
import tempfile
import unittest
from pathlib import Path
from aegisforge.analyzers import analyze_python, analyze_text
from aegisforge.reporters import to_json, to_sarif, to_text
from aegisforge.scanner import scan_directory

class AnalyzerTests(unittest.TestCase):
    def test_detects_dynamic_python_execution(self):
        findings = analyze_python("eval(user_input)\n", "app.py")
        self.assertIn("AF-PY-001", {item.rule_id for item in findings})

    def test_detects_shell_true(self):
        findings = analyze_python("subprocess.run(command, shell=True)\n", "app.py")
        self.assertIn("AF-PY-002", {item.rule_id for item in findings})

    def test_does_not_execute_scanned_source(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "executed.txt"
            source = Path(folder) / "sample.py"
            source.write_text(f"open({str(marker)!r}, 'w').write('bad')\neval('1+1')\n")
            result = scan_directory(folder)
            self.assertTrue(result.findings)
            self.assertFalse(marker.exists())

    def test_secret_value_is_redacted_from_evidence(self):
        findings = analyze_text('API_TOKEN = "sensitive-value-123"\n', "settings.py")
        self.assertEqual(len(findings), 1)
        self.assertNotIn("sensitive-value-123", findings[0].evidence)
        self.assertIn("***", findings[0].evidence)

    def test_invalid_python_is_reported_as_incomplete_ast_analysis(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "broken.py"
            source.write_text("def broken(:\\n    pass\\n", encoding="utf-8")
            result = scan_directory(folder)
            self.assertEqual(result.scanned_files, 1)
            self.assertTrue(any("AST analysis skipped" in error for error in result.errors))

    def test_reports_are_machine_readable(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "settings.py").write_text("eval(user_input)\n")
            result = scan_directory(folder)
            payload = json.loads(to_json(result))
            sarif = json.loads(to_sarif(result))
            self.assertEqual(payload["tool"]["name"], "AegisForge")
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertIn("AegisForge scan", to_text(result))

    def test_scan_skips_symlink_files(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "secret.py"
            target.write_text("eval(x)\n")
            link = Path(folder) / "linked.py"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable on this platform")
            result = scan_directory(folder)
            self.assertEqual(result.scanned_files, 0)
            self.assertFalse(result.findings)

if __name__ == "__main__":
    unittest.main()

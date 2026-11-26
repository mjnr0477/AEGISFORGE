import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from aegisforge.cli import main

class CLITests(unittest.TestCase):
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

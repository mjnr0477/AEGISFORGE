import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


DEMO_PATH = Path(__file__).resolve().parents[1] / "examples" / "simulation_demo.py"
SPEC = importlib.util.spec_from_file_location("aegisforge_simulation_demo", DEMO_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the AegisForge simulation demo")
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


class SimulationDemoTests(unittest.TestCase):
    def _run_in_temporary_directory(self, answers):
        original_directory = Path.cwd()
        with tempfile.TemporaryDirectory() as folder:
            try:
                os.chdir(folder)
                output = io.StringIO()
                with patch("builtins.input", side_effect=answers), contextlib.redirect_stdout(output):
                    result = DEMO.main()
                ledger = Path(".aegisforge/simulation-audit.jsonl")
                entries = [
                    json.loads(line)
                    for line in ledger.read_text(encoding="utf-8").splitlines()
                ]
                return result, output.getvalue(), entries
            finally:
                os.chdir(original_directory)

    def test_approving_both_simulated_mutations_records_each_capability(self):
        result, output, entries = self._run_in_temporary_directory(["y", "y"])
        self.assertEqual(result, 0)
        self.assertIn("'simulated': True", output)
        approvals = [
            entry["event"]
            for entry in entries
            if entry["event"]["type"] == "approval_issued"
        ]
        self.assertEqual(
            [event["capability"] for event in approvals],
            ["service.restart", "device.control"],
        )
        decisions = [
            entry["event"]
            for entry in entries
            if entry["event"]["type"] == "authorization_decision"
        ]
        self.assertEqual(len(decisions), 3)
        self.assertTrue(all(event["allowed"] for event in decisions))

    def test_declining_mutations_records_no_approval_and_does_not_change_state(self):
        result, output, entries = self._run_in_temporary_directory(["n", "n"])
        self.assertEqual(result, 0)
        self.assertIn("Skipped restart.", output)
        self.assertIn("Skipped set_mode.", output)
        approvals = [
            entry["event"]
            for entry in entries
            if entry["event"]["type"] == "approval_issued"
        ]
        self.assertEqual(approvals, [])
        decisions = [
            entry["event"]
            for entry in entries
            if entry["event"]["type"] == "authorization_decision"
        ]
        self.assertEqual(len(decisions), 1)
        self.assertTrue(decisions[0]["allowed"])
        self.assertEqual(decisions[0]["capability"], "service.inspect")


if __name__ == "__main__":
    unittest.main()

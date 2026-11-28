import contextlib
import io
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch


from aegisforge import simulation_demo as DEMO


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


    def test_non_interactive_eof_declines_all_mutations_safely(self):
        original_directory = os.getcwd()
        with tempfile.TemporaryDirectory() as folder:
            try:
                os.chdir(folder)
                output = io.StringIO()
                with patch("builtins.input", side_effect=EOFError), contextlib.redirect_stdout(output):
                    result = DEMO.main()
                self.assertEqual(result, 0)
                self.assertIn("no approval was provided", output.getvalue())
                entries = [
                    json.loads(line)
                    for line in Path(".aegisforge/simulation-audit.jsonl").read_text(
                        encoding="utf-8"
                    ).splitlines()
                ]
                self.assertFalse(any(
                    entry["event"]["type"] == "approval_issued" for entry in entries
                ))
            finally:
                os.chdir(original_directory)

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

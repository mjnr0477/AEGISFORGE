import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aegisforge.autonomy import create_local_registry
from aegisforge.cli import main

class ProjectMapCLITests(unittest.TestCase):
    def test_map_command_emits_relative_structural_index(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"sample"
            root.mkdir()
            (root/"app.py").write_text("import os\n\ndef start():\n    return os.getcwd()\n",encoding="utf-8")
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                status=main(["map",str(root),"--format","json"])
            payload=json.loads(output.getvalue())
        self.assertEqual(status,0)
        self.assertEqual(payload["operation"],"project_map")
        self.assertEqual(payload["summary"]["functions"],1)
        self.assertEqual(payload["summary"]["calls"],1)
        self.assertEqual(payload["modules"][0]["path"],"app.py")
        self.assertNotIn(str(root),output.getvalue())

    def test_map_command_reports_partial_analysis_with_exit_two(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"broken.py").write_text("def broken(:\n",encoding="utf-8")
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                status=main(["map",str(root),"--format","json"])
            payload=json.loads(output.getvalue())
        self.assertEqual(status,2)
        self.assertTrue(payload["warnings"])

    def test_builtin_registry_exposes_project_map_as_read_only(self):
        catalog={item["name"]:item for item in create_local_registry().describe()}
        self.assertIn("map_project",catalog)
        self.assertFalse(catalog["map_project"]["mutates"])

if __name__ == "__main__":
    unittest.main()

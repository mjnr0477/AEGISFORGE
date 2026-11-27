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
            (root/"app.py").write_text("import util\n\ndef start():\n    return util.work()\n",encoding="utf-8")
            (root/"util.py").write_text("import app\ndef work(): return 1\n",encoding="utf-8")
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                status=main(["map",str(root),"--format","json"])
            payload=json.loads(output.getvalue())
        self.assertEqual(status,0)
        self.assertEqual(payload["operation"],"project_map")
        self.assertEqual(payload["summary"]["functions"],2)
        self.assertEqual(payload["summary"]["calls"],1)
        self.assertEqual(payload["summary"]["dependency_edges"],2)
        self.assertEqual(payload["summary"]["cross_file_calls"],1)
        self.assertEqual(payload["summary"]["circular_dependency_groups"],1)
        self.assertEqual(payload["circular_dependencies"][0]["modules"],["app", "util"])
        self.assertEqual(payload["circular_dependencies"][0]["resolution"],"direct")
        self.assertEqual(len(payload["circular_dependencies"][0]["edges"]),2)
        self.assertEqual(payload["circular_dependencies"][0]["edges"][0]["line"],1)
        self.assertEqual(payload["cross_file_calls"][0]["source_module"],"app")
        self.assertEqual(payload["cross_file_calls"][0]["target_symbol"],"work")
        self.assertEqual(payload["dependencies"][0]["source_module"],"app")
        self.assertEqual(payload["dependencies"][0]["target_module"],"util")
        self.assertEqual(payload["modules"][0]["path"],"app.py")
        self.assertNotIn(str(root),output.getvalue())

    def test_map_text_output_lists_internal_dependency_edges(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text(
                "import helper\ndef start(): helper.work()\n",
                encoding="utf-8",
            )
            (root / "helper.py").write_text("def work(): return 1\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["map", str(root)])
        self.assertEqual(status, 0)
        self.assertIn("DEPENDENCY app -> helper", output.getvalue())
        self.assertIn("CROSS-FILE app.start -> helper.work", output.getvalue())

    def test_map_text_output_lists_circular_import_groups(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "alpha.py").write_text("import beta\n", encoding="utf-8")
            (root / "beta.py").write_text("import alpha\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["map", str(root)])
        self.assertEqual(status, 0)
        self.assertIn("CIRCULAR IMPORT GROUPS", output.getvalue())
        self.assertIn("CYCLE [direct] alpha, beta [edges=2]", output.getvalue())
        self.assertIn("alpha -> beta [line 1, import, direct]", output.getvalue())
        self.assertIn("beta -> alpha [line 1, import, direct]", output.getvalue())

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

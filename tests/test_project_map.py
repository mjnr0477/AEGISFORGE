import tempfile
import unittest
from pathlib import Path

from aegisforge.project_map import build_project_map

class ProjectMapTests(unittest.TestCase):
    def test_indexes_modules_imports_classes_functions_and_calls(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"main.py").write_text(
                "from service import Client\n"
                "import os as operating_system\n"
                "\n"
                "class Worker:\n"
                "    def run(self, value):\n"
                "        client = Client()\n"
                "        return client.process(value)\n"
                "\n"
                "def start():\n"
                "    worker = Worker()\n"
                "    return worker.run('x')\n",
                encoding="utf-8",
            )
            (root/"service.py").write_text(
                "class Client:\n"
                "    def process(self, value):\n"
                "        return str(value)\n",
                encoding="utf-8",
            )
            result=build_project_map(root)
        self.assertEqual(result.scanned_files,2)
        self.assertEqual(result.summary["modules"],2)
        symbols=[symbol.qualified_name for module in result.modules for symbol in module.symbols]
        self.assertIn("Worker",symbols)
        self.assertIn("Worker.run",symbols)
        self.assertIn("start",symbols)
        self.assertIn("Client.process",symbols)
        imports=[item.module for module in result.modules for item in module.imports]
        self.assertIn("service",imports)
        self.assertIn("os",imports)
        calls=[item.callee for module in result.modules for item in module.calls]
        self.assertIn("Client",calls)
        self.assertIn("client.process",calls)
        self.assertIn("Worker",calls)
        self.assertIn("worker.run",calls)

    def test_resolves_absolute_and_relative_internal_import_dependencies(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "app.py").write_text(
                "import pkg.service as service\n"
                "from pkg import service as imported_service\n"
                "from os import path\n",
                encoding="utf-8",
            )
            package = root / "pkg"
            (package / "sub").mkdir(parents=True)
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "service.py").write_text("def run(): pass\n", encoding="utf-8")
            (package / "common.py").write_text("VALUE = 1\n", encoding="utf-8")
            (package / "consumer.py").write_text(
                "from . import service\n"
                "from .sub import worker\n",
                encoding="utf-8",
            )
            (package / "sub" / "__init__.py").write_text("", encoding="utf-8")
            (package / "sub" / "worker.py").write_text(
                "from .. import common\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        edges = {
            (item.source_module, item.target_module, item.resolution)
            for item in result.dependencies
        }
        self.assertIn(("app", "pkg.service", "direct"), edges)
        self.assertIn(("app", "pkg", "direct"), edges)
        self.assertIn(("app", "pkg.service", "possible_submodule"), edges)
        self.assertIn(("pkg.consumer", "pkg", "direct"), edges)
        self.assertIn(("pkg.consumer", "pkg.service", "possible_submodule"), edges)
        self.assertIn(("pkg.consumer", "pkg.sub", "direct"), edges)
        self.assertIn(("pkg.consumer", "pkg.sub.worker", "possible_submodule"), edges)
        self.assertIn(("pkg.sub.worker", "pkg", "direct"), edges)
        self.assertIn(("pkg.sub.worker", "pkg.common", "possible_submodule"), edges)
        self.assertFalse(any(item.target_module == "os" for item in result.dependencies))
        self.assertEqual(result.summary["dependency_edges"], len(result.dependencies))

    def test_resolves_internal_imports_from_namespace_packages(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "namespace" / "sub").mkdir(parents=True)
            (root / "app.py").write_text("from namespace import service\n", encoding="utf-8")
            (root / "namespace" / "service.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "namespace" / "sub" / "worker.py").write_text(
                "from .. import service\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        edges = {(item.source_module, item.target_module, item.resolution) for item in result.dependencies}
        self.assertIn(("app", "namespace.service", "possible_submodule"), edges)
        self.assertIn(("namespace.sub.worker", "namespace.service", "possible_submodule"), edges)

    def test_reports_syntax_failures_instead_of_silently_omitting_them(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"broken.py").write_text("def broken(:\n",encoding="utf-8")
            result=build_project_map(root)
        self.assertEqual(result.scanned_files,1)
        self.assertEqual(result.summary["modules"],0)
        self.assertTrue(any("syntax error" in warning for warning in result.warnings))

    def test_does_not_execute_indexed_source(self):
        marker=Path("/tmp/aegisforge-project-map-must-not-execute")
        marker.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"app.py").write_text(
                f"open({str(marker)!r}, 'w').write('bad')\n"
                "def safe():\n    return 1\n",
                encoding="utf-8",
            )
            result=build_project_map(root)
        self.assertEqual(result.summary["functions"],1)
        self.assertFalse(marker.exists())

    def test_skips_symlinked_python_sources(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root=Path(temp)
            source=Path(outside)/"outside.py"
            source.write_text("def outside(): pass\n",encoding="utf-8")
            try:
                (root/"linked.py").symlink_to(source)
            except (OSError,NotImplementedError):
                self.skipTest("symlinks unavailable")
            result=build_project_map(root)
        self.assertEqual(result.scanned_files,0)
        self.assertEqual(result.summary["functions"],0)

    def test_json_export_uses_relative_paths_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"private-project"
            root.mkdir()
            (root/"sub.py").write_text("def run(): pass\n",encoding="utf-8")
            payload=build_project_map(root).to_dict()
        self.assertEqual(payload["project"],"private-project")
        self.assertNotIn(str(root),str(payload))
        self.assertEqual(payload["modules"][0]["path"],"sub.py")

    def test_resource_limit_warnings_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"oversized.py").write_bytes(b"x"*(1_000_001))
            result=build_project_map(root)
        self.assertTrue(any("file size limit exceeded" in warning for warning in result.warnings))
        self.assertEqual(result.scanned_files,0)

if __name__ == "__main__":
    unittest.main()

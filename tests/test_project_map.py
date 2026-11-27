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

    def test_resolves_relative_imports_from_a_scanned_package_root_init(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "__init__.py").write_text(
                "from . import service\n"
                "from .service import execute\n"
                "def start():\n"
                "    service.run()\n"
                "    execute()\n",
                encoding="utf-8",
            )
            (root / "service.py").write_text(
                "def run(): return 1\n"
                "def execute(): return 2\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        dependencies = {(item.source_module, item.target_module) for item in result.dependencies}
        self.assertIn(("__init__", "service"), dependencies)
        calls = {(item.source_module, item.target_module, item.target_symbol) for item in result.cross_file_calls}
        self.assertIn(("__init__", "service", "run"), calls)
        self.assertIn(("__init__", "service", "execute"), calls)

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

    def test_ignores_relative_imports_that_escape_the_package_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "pkg" / "sub"
            package.mkdir(parents=True)
            (root / "common.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
            (root / "pkg" / "sub" / "worker.py").write_text(
                "from ... import common\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertFalse(any(
            item.source_module == "pkg.sub.worker" and item.target_module == "common"
            for item in result.dependencies
        ))

    def test_does_not_resolve_duplicate_module_names(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tool").mkdir()
            (root / "main.py").write_text("import tool\n", encoding="utf-8")
            (root / "helper.py").write_text("VALUE = 0\n", encoding="utf-8")
            (root / "tool.py").write_text("import helper\nVALUE = 1\n", encoding="utf-8")
            (root / "tool" / "__init__.py").write_text("import helper\nVALUE = 2\n", encoding="utf-8")
            result = build_project_map(root)

        self.assertFalse(any(
            item.target_module == "tool" or item.source_module == "tool"
            for item in result.dependencies
        ))

    def test_resolves_imported_function_and_module_calls_across_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text(
                "def execute(): return 1\n"
                "class Runner:\n"
                "    def run(self): return execute()\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from service import execute as invoke\n"
                "import service as svc\n"
                "def start():\n"
                "    invoke()\n"
                "    svc.execute()\n"
                "    svc.Runner.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        calls = {(item.caller, item.callee, item.target_module, item.target_symbol, item.resolution)
                 for item in result.cross_file_calls}
        self.assertIn(("start", "invoke", "service", "execute", "direct"), calls)
        self.assertIn(("start", "svc.execute", "service", "execute", "direct"), calls)
        self.assertIn(("start", "svc.Runner.run", "service", "Runner.run", "direct"), calls)
        self.assertEqual(result.summary["cross_file_calls"], 3)

    def test_resolves_calls_through_possible_submodule_imports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "pkg"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "worker.py").write_text("def run(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from pkg import worker as imported_worker\n"
                "def start(): imported_worker.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(len(result.cross_file_calls), 1)
        call = result.cross_file_calls[0]
        self.assertEqual(call.source_module, "app")
        self.assertEqual(call.target_module, "pkg.worker")
        self.assertEqual(call.target_symbol, "run")
        self.assertEqual(call.resolution, "possible_submodule")

    def test_does_not_resolve_import_aliases_shadowed_in_function_scopes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text("def execute(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from service import execute as invoke\n"
                "def parameter_shadow(invoke): invoke()\n"
                "def assignment_shadow():\n"
                "    invoke = safe_callable\n"
                "    invoke()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])

    def test_does_not_resolve_function_local_import_as_module_import(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text("def execute(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "def start():\n"
                "    import service as svc\n"
                "    svc.execute()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])
        self.assertEqual(result.modules[0].imports[0].scope, "start")

    def test_does_not_resolve_conditional_module_imports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text("def execute(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from typing import TYPE_CHECKING\n"
                "if TYPE_CHECKING:\n"
                "    import service as svc\n"
                "def start(): svc.execute()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])
        conditional_import = next(item for item in result.modules[0].imports if item.alias == "svc")
        self.assertTrue(conditional_import.conditional)

    def test_does_not_resolve_optional_import_from_module_try_block(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text("def execute(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "try:\n"
                "    import service as svc\n"
                "except ImportError:\n"
                "    svc = fallback\n"
                "def start(): svc.execute()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])

    def test_does_not_treat_package_data_attribute_as_submodule_import(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "pkg"
            package.mkdir()
            (package / "__init__.py").write_text(
                "worker = create_worker()\n",
                encoding="utf-8",
            )
            (package / "worker.py").write_text(
                "def run(): return 1\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from pkg import worker\n"
                "def start(): worker.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        package_record = next(module for module in result.modules if module.module == "pkg")
        self.assertIn("worker", package_record.module_bindings)
        self.assertEqual(result.cross_file_calls, [])

    def test_does_not_resolve_module_alias_after_module_level_rebinding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text("def execute(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import service as svc\n"
                "svc = replacement\n"
                "def start(): svc.execute()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])

    def test_resolves_dotted_import_using_actual_package_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "pkg"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "service.py").write_text("def run(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import pkg.service\n"
                "def start(): pkg.service.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(len(result.cross_file_calls), 1)
        self.assertEqual(result.cross_file_calls[0].target_module, "pkg.service")
        self.assertEqual(result.cross_file_calls[0].target_symbol, "run")

    def test_does_not_resolve_dotted_import_when_package_binding_is_shadowed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "pkg"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "service.py").write_text("def run(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import pkg.service\n"
                "def start(pkg): pkg.service.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])

    def test_does_not_resolve_imported_module_after_local_attribute_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text("def run(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import service as svc\n"
                "def start():\n"
                "    svc.run = replacement\n"
                "    svc.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])

    def test_does_not_resolve_imported_module_after_module_attribute_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text("def run(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import service as svc\n"
                "svc.run = replacement\n"
                "def start(): svc.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])

    def test_does_not_resolve_duplicate_module_level_import_aliases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text("def run(): return 1\n", encoding="utf-8")
            (root / "other.py").write_text("def run(): return 2\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import service as svc\n"
                "import other as svc\n"
                "def start(): svc.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])

    def test_does_not_resolve_alias_overwritten_by_unresolved_external_import(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text("def run(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import service as svc\n"
                "import external_package as svc\n"
                "def start(): svc.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])

    def test_does_not_resolve_calls_in_modules_with_star_imports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "service.py").write_text("def run(): return 1\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from external_package import *\n"
                "import service as svc\n"
                "def start(): svc.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])

    def test_does_not_guess_when_package_symbol_and_submodule_are_both_ambiguous(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "pkg"
            package.mkdir()
            (package / "__init__.py").write_text(
                "def worker(): return 1\n"
                "def worker(): return 2\n",
                encoding="utf-8",
            )
            (package / "worker.py").write_text("def run(): return 3\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from pkg import worker\n"
                "def start(): worker.run()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(result.cross_file_calls, [])

    def test_labels_package_symbol_and_submodule_name_collisions_ambiguous(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "pkg"
            package.mkdir()
            (package / "__init__.py").write_text("def worker(): return 1\n", encoding="utf-8")
            (package / "worker.py").write_text("def run(): return 2\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from pkg import worker\n"
                "def start(): worker()\n",
                encoding="utf-8",
            )
            result = build_project_map(root)

        self.assertEqual(len(result.cross_file_calls), 1)
        self.assertEqual(result.cross_file_calls[0].resolution, "ambiguous")

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

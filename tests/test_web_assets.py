import unittest
from aegisforge import __version__
from importlib.resources import files

class WebAssetTests(unittest.TestCase):
    def test_browser_workbench_assets_are_packaged(self):
        package=files("aegisforge")
        for name in ("index.html","app.css","app.js"):
            with self.subTest(asset=name):
                resource=package.joinpath("web",name)
                self.assertTrue(resource.is_file(),f"missing package asset: {name}")

    def test_browser_version_matches_python_package(self):
        html=files("aegisforge").joinpath("web","index.html").read_text(encoding="utf-8")
        self.assertIn(f'id="version">v{__version__}</span>',html)

    def test_html_uses_same_origin_assets(self):
        html=files("aegisforge").joinpath("web","index.html").read_text(encoding="utf-8")
        self.assertIn('href="/app.css"',html)
        self.assertIn('src="/app.js"',html)
        self.assertNotIn('<script src="https://',html)
        self.assertNotIn('<link rel="stylesheet" href="https://',html)

    def test_local_workbench_has_project_structure_panel(self):
        html=files("aegisforge").joinpath("web","index.html").read_text(encoding="utf-8")
        script=files("aegisforge").joinpath("web","app.js").read_text(encoding="utf-8")
        self.assertIn('id="projectMap"',html)
        self.assertIn('renderProjectMap',script)
        self.assertIn('cycle.edges',script)
        self.assertIn('edge.line',script)

    def test_finding_rendering_does_not_use_inner_html(self):
        script=files("aegisforge").joinpath("web","app.js").read_text(encoding="utf-8")
        self.assertNotIn(".innerHTML",script)
        self.assertIn("textContent",script)

if __name__ == "__main__":
    unittest.main()

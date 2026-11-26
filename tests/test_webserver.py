import http.client
import io
import json
import stat
import threading
import unittest
import zipfile
from pathlib import Path

from aegisforge.webserver import create_server, scan_archive_bytes

def make_zip(entries):
    output=io.BytesIO()
    with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            archive.writestr(name,content)
    return output.getvalue()

class ArchiveScanTests(unittest.TestCase):
    def test_scans_supported_source_without_executing_it(self):
        marker=Path("/tmp/aegisforge-upload-must-not-execute")
        marker.unlink(missing_ok=True)
        archive=make_zip([("project/app.py",f"open({str(marker)!r}, 'w').write('bad')\neval(user_input)\n")])
        result=scan_archive_bytes(archive)
        self.assertEqual(result["scanned_files"],1)
        self.assertIn("AF-PY-001",{item["rule_id"] for item in result["findings"]})
        self.assertFalse(marker.exists())

    def test_scan_includes_python_project_map(self):
        archive=make_zip([
            ("project/main.py","from service import Service\nclass App:\n    def run(self):\n        return Service().open()\n"),
            ("project/service.py","class Service:\n    def open(self):\n        return True\n"),
        ])
        result=scan_archive_bytes(archive)
        project_map=result["project_map"]
        self.assertEqual(project_map["operation"],"project_map")
        self.assertEqual(project_map["summary"]["modules"],2)
        self.assertGreaterEqual(project_map["summary"]["classes"],2)
        self.assertEqual(project_map["modules"][0]["path"],"main.py")
        self.assertNotIn("aegisforge-upload-",str(project_map))

    def test_rejects_parent_traversal_paths(self):
        archive=make_zip([("../outside.py","eval(x)\n")])
        with self.assertRaisesRegex(ValueError,"unsafe archive path"):
            scan_archive_bytes(archive)

    def test_rejects_absolute_paths(self):
        archive=make_zip([("/tmp/outside.py","eval(x)\n")])
        with self.assertRaisesRegex(ValueError,"unsafe archive path"):
            scan_archive_bytes(archive)

    def test_rejects_windows_path_separators(self):
        archive=make_zip([(r"..\\outside.py","eval(x)\n")])
        with self.assertRaisesRegex(ValueError,"unsafe archive path"):
            scan_archive_bytes(archive)

    def test_rejects_symlink_entries(self):
        output=io.BytesIO()
        with zipfile.ZipFile(output,"w") as archive:
            info=zipfile.ZipInfo("project/link.py")
            info.create_system=3
            info.external_attr=(stat.S_IFLNK|0o777)<<16
            archive.writestr(info,"../../outside.py")
        with self.assertRaisesRegex(ValueError,"symlink"):
            scan_archive_bytes(output.getvalue())

    def test_rejects_duplicate_case_insensitive_paths(self):
        archive=make_zip([("project/App.py","print(1)\n"),("project/app.py","print(2)\n")])
        with self.assertRaisesRegex(ValueError,"duplicate archive path"):
            scan_archive_bytes(archive)

    def test_rejects_corrupt_zip(self):
        with self.assertRaisesRegex(ValueError,"invalid ZIP archive"):
            scan_archive_bytes(b"not a zip file")

class LocalServerTests(unittest.TestCase):
    def setUp(self):
        self.server=create_server("127.0.0.1",0)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.port=self.server.server_address[1]
        self.host=f"127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_serves_local_workbench(self):
        connection=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        connection.request("GET","/",headers={"Host":self.host})
        response=connection.getresponse()
        body=response.read().decode()
        self.assertEqual(response.status,200)
        self.assertIn("AegisForge",body)
        self.assertEqual(response.getheader("X-Content-Type-Options"),"nosniff")
        connection.close()

    def test_rejects_cross_origin_upload(self):
        archive=make_zip([("app.py","eval(x)\n")])
        connection=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        connection.request("POST","/api/scan",body=archive,headers={
            "Host":self.host,"Origin":"http://attacker.example","Content-Type":"application/zip"
        })
        response=connection.getresponse()
        payload=json.loads(response.read())
        self.assertEqual(response.status,403)
        self.assertIn("origin",payload["error"].lower())
        connection.close()

    def test_rejects_host_header_for_non_local_domain(self):
        connection=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        connection.request("GET","/",headers={"Host":"attacker.example"})
        response=connection.getresponse()
        response.read()
        self.assertEqual(response.status,403)
        connection.close()

    def test_accepts_same_origin_zip_upload(self):
        archive=make_zip([("project/app.py","eval(user_input)\n")])
        connection=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        connection.request("POST","/api/scan",body=archive,headers={
            "Host":self.host,"Origin":f"http://{self.host}","Content-Type":"application/zip"
        })
        response=connection.getresponse()
        payload=json.loads(response.read())
        self.assertEqual(response.status,200)
        self.assertEqual(payload["scanned_files"],1)
        self.assertIn("AF-PY-001",{item["rule_id"] for item in payload["findings"]})
        self.assertEqual(payload["root"],"uploaded-project")
        connection.close()

if __name__ == "__main__":
    unittest.main()

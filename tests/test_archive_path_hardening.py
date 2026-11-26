import io
import socket
import threading
import unittest
import zipfile

from aegisforge.webserver import create_server, scan_archive_bytes

def make_zip(entries):
    output=io.BytesIO()
    with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            archive.writestr(name,content)
    return output.getvalue()

class ArchivePathHardeningTests(unittest.TestCase):
    def test_rejects_colon_in_non_first_path_component(self):
        archive=make_zip([("project/app.py:alternate","eval(x)\n")])
        with self.assertRaisesRegex(ValueError,"unsafe archive path"):
            scan_archive_bytes(archive)

    def test_skips_dependency_folders_case_insensitively(self):
        archive=make_zip([("Project/Node_Modules/injected.py","eval(user_input)\n")])
        result=scan_archive_bytes(archive)
        self.assertEqual(result["scanned_files"],0)
        self.assertEqual(result["findings"],[])

class IPv6LoopbackTests(unittest.TestCase):
    def test_server_can_bind_only_to_ipv6_loopback_when_available(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 is not available")
        try:
            server=create_server("::1",0)
        except OSError as exc:
            self.skipTest(f"IPv6 loopback binding unavailable: {exc}")
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        try:
            thread.start()
            self.assertEqual(server.server_address[0],"::1")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

if __name__ == "__main__":
    unittest.main()

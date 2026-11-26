import http.client
import io
import tempfile
import threading
import unittest
import zipfile
from unittest.mock import patch

from aegisforge.cli import main
from aegisforge.webserver import ArchiveValidationError, create_server, scan_archive_bytes

class ArchiveLimitTests(unittest.TestCase):
    def test_rejects_high_compression_ratio_source(self):
        output=io.BytesIO()
        with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("app.py","x" * 100_000)
        with self.assertRaisesRegex(ArchiveValidationError,"compression ratio"):
            scan_archive_bytes(output.getvalue())

    def test_rejects_windows_reserved_device_names(self):
        output=io.BytesIO()
        with zipfile.ZipFile(output,"w") as archive:
            archive.writestr("project/CON/app.py","eval(x)\n")
        with self.assertRaisesRegex(ArchiveValidationError,"unsafe archive path"):
            scan_archive_bytes(output.getvalue())

    def test_server_requires_loopback_literal(self):
        for host in ("0.0.0.0","192.0.2.10","localhost"):
            with self.subTest(host=host):
                with self.assertRaisesRegex(ValueError,"loopback"):
                    create_server(host,8765)

    def test_server_validates_port(self):
        with self.assertRaisesRegex(ValueError,"port"):
            create_server("127.0.0.1",-1)

class LocalServerBoundaryTests(unittest.TestCase):
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

    def test_rejects_wrong_content_type(self):
        connection=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        connection.request("POST","/api/scan",body=b"data",headers={
            "Host":self.host,"Origin":f"http://{self.host}","Content-Type":"text/plain"
        })
        response=connection.getresponse()
        self.assertEqual(response.status,415)
        connection.close()

    def test_rejects_post_without_origin(self):
        connection=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        connection.request("POST","/api/scan",body=b"data",headers={
            "Host":self.host,"Content-Type":"application/zip"
        })
        response=connection.getresponse()
        self.assertEqual(response.status,403)
        connection.close()

    def test_rejects_oversized_content_length_before_read(self):
        connection=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        connection.putrequest("POST","/api/scan")
        connection.putheader("Host",self.host)
        connection.putheader("Origin",f"http://{self.host}")
        connection.putheader("Content-Type","application/zip")
        connection.putheader("Content-Length",str(26*1024*1024))
        connection.endheaders()
        response=connection.getresponse()
        self.assertEqual(response.status,413)
        connection.close()

class ServeCommandTests(unittest.TestCase):
    def test_serve_command_dispatches_to_loopback_server(self):
        with patch("aegisforge.cli.serve") as serve:
            status=main(["serve","--host","127.0.0.1","--port","8765"])
        self.assertEqual(status,0)
        serve.assert_called_once_with("127.0.0.1",8765)

if __name__ == "__main__":
    unittest.main()

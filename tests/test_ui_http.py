# -*- coding: utf-8 -*-
"""UI 的进程内 HTTP 测试（不启动 --ui，也不依赖浏览器）。"""
from __future__ import annotations

import http.client
import json
import os
import threading
import unittest
from http.server import ThreadingHTTPServer

from certdiag.ui import _Handler

CMD = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")


class TestUiHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def test_index(self):
        st, data = self.req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("certdiag", data.decode("utf-8"))

    def test_health(self):
        st, data = self.req("GET", "/api/health")
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(data)["ok"])

    def test_unknown_routes(self):
        self.assertEqual(self.req("GET", "/nope")[0], 404)
        self.assertEqual(self.req("POST", "/nope", b"{}")[0], 404)

    def test_bad_host_rejected(self):
        st, _ = self.req("GET", "/", headers={"Host": "evil.example"})
        self.assertEqual(st, 403)

    def test_scan_errors(self):
        for payload, needle in (({}, "path"), ({"path": "Z:/nope"}, "不存在"),
                                ({"path": os.path.dirname(CMD)}, "目录")):
            st, data = self.req("POST", "/api/scan", json.dumps(payload).encode())
            self.assertEqual(st, 200)
            self.assertIn(needle, json.loads(data).get("error", ""))

    @unittest.skipUnless(os.path.exists(CMD), "需要 Windows 系统文件")
    def test_scan_valid(self):
        st, data = self.req("POST", "/api/scan",
                            json.dumps({"path": CMD, "offline": True, "no_probe": True}).encode())
        self.assertEqual(st, 200)
        rep = json.loads(data)
        self.assertIn("diagnosis", rep)

    def test_export_json(self):
        body = {"report": {"x": 1}, "fmt": "json"}
        st, data = self.req("POST", "/api/export", json.dumps(body).encode())
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(data), {"x": 1})

    def test_export_malformed(self):
        body = {"report": {"diagnosis": None}, "fmt": "md"}
        st, data = self.req("POST", "/api/export", json.dumps(body).encode())
        self.assertEqual(st, 400)
        self.assertIn("结构不完整", json.loads(data)["error"])

    def test_upload(self):
        st, data = self.req("POST", "/api/upload?offline=1&no_probe=1",
                            b"MZ" + b"\0" * 64, {"X-Filename": "up.exe"})
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(data).get("uploaded_name"), "up.exe")

    def test_upload_empty(self):
        st, data = self.req("POST", "/api/upload", b"", {"Content-Length": "0"})
        self.assertEqual(st, 200)
        self.assertIn("没有收到", json.loads(data)["error"])

    def test_payload_too_large(self):
        st, data = self.req("POST", "/api/scan", b"{}",
                            {"Content-Length": str(9 * 1024 * 1024)})
        self.assertEqual(st, 413)

# -*- coding: utf-8 -*-
"""探测模块的测试：用本地 HTTP 服务，不依赖外网。"""
from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from certdiag.probe import probe_all, probe_url


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静音
        pass

    def do_HEAD(self):
        self._respond()

    def do_GET(self):
        self._respond()

    def _respond(self):
        if self.path == "/ok":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


class TestProbeLocal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_ok(self):
        r = probe_url(self.url("/ok"), timeout=3, allow_private=True)
        self.assertEqual(r.http, "200")
        self.assertEqual(r.category, "ok")

    def test_404_is_http_error(self):
        r = probe_url(self.url("/missing"), timeout=3, allow_private=True)
        self.assertEqual(r.http, "404")
        self.assertIn(r.category, ("http_error", "ok"))

    def test_redirect_not_followed(self):
        r = probe_url(self.url("/redir"), timeout=3, allow_private=True)
        self.assertEqual(r.http, "302")

    def test_private_skipped_by_default(self):
        r = probe_url(self.url("/ok"), timeout=3)
        self.assertEqual(r.category, "skipped_private")

    def test_probe_all(self):
        rs = probe_all([self.url("/ok"), self.url("/missing")], timeout=3,
                       allow_private=True)
        self.assertEqual(len(rs), 2)
        self.assertTrue(any(r.category == "ok" for r in rs))

    def test_bad_scheme(self):
        r = probe_url("file:///C:/Windows/win.ini", timeout=2, allow_private=True)
        self.assertNotEqual(r.category, "ok")

    def test_dns_failure(self):
        r = probe_url("http://nonexistent.invalid/x", timeout=2, allow_private=True)
        self.assertIn(r.category, ("dns_fail", "blocked", "http_error", "unknown"))

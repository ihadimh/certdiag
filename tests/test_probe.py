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


class TestProbeProxyFallbacks(unittest.TestCase):
    """直连失败 + 代理可达时，不能判"不可达"。这些分支靠 mock 触发。"""

    def _proxy(self):
        from certdiag.proxy import ProxyInfo
        return ProxyInfo(True, "http://127.0.0.1:9", "", "", "env")

    def test_dns_fail_via_proxy(self):
        from unittest import mock

        from certdiag.probe import probe_url

        def via_proxy(url, timeout, r):
            r.category, r.detail = "ok", "代理可达"
            return True

        with mock.patch("certdiag.proxy.detect", return_value=self._proxy()), \
             mock.patch("certdiag.probe._resolve", return_value=("fail", [], "dns")), \
             mock.patch("certdiag.probe._http_via_proxy", side_effect=via_proxy):
            r = probe_url("http://example.com/a.crl", timeout=1)
        self.assertEqual(r.category, "ok")

    def test_tcp_fail_via_proxy(self):
        from unittest import mock

        from certdiag.probe import probe_url

        def via_proxy(url, timeout, r):
            r.category, r.detail = "ok", "代理可达"
            return True

        with mock.patch("certdiag.proxy.detect", return_value=self._proxy()), \
             mock.patch("certdiag.probe._resolve", return_value=("ok", ["1.2.3.4"], "")), \
             mock.patch("certdiag.probe._tcp", return_value=("timeout", "tcp timeout")), \
             mock.patch("certdiag.probe._http_via_proxy", side_effect=via_proxy):
            r = probe_url("http://example.com/a.crl", timeout=1)
        self.assertEqual(r.category, "ok")

    def test_tls_error(self):
        from unittest import mock

        from certdiag.probe import probe_url

        with mock.patch("certdiag.proxy.detect", return_value=type("P", (), {"enabled": False})()), \
             mock.patch("certdiag.probe._resolve", return_value=("ok", ["1.2.3.4"], "")), \
             mock.patch("certdiag.probe._tcp", return_value=("ok", "")), \
             mock.patch("certdiag.probe._http", return_value=("", "error", "TLS 握手失败")):
            r = probe_url("http://example.com/a.crl", timeout=1)
        self.assertEqual(r.category, "tls_error")

    def test_ocsp_inconclusive(self):
        from unittest import mock

        from certdiag.probe import probe_url

        with mock.patch("certdiag.proxy.detect", return_value=type("P", (), {"enabled": False})()), \
             mock.patch("certdiag.probe._resolve", return_value=("ok", ["1.2.3.4"], "")), \
             mock.patch("certdiag.probe._tcp", return_value=("ok", "")), \
             mock.patch("certdiag.probe._http", return_value=("", "skip", "GET 不支持")):
            r = probe_url("http://ocsp.example.com/x", timeout=1)
        self.assertEqual(r.kind, "ocsp")
        self.assertEqual(r.category, "inconclusive")

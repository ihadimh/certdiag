# -*- coding: utf-8 -*-
"""覆盖率补白（二）：PE 结构边界、HTTP 错误分支、CLI 过滤与冲突。"""
from __future__ import annotations

import os
import socket
import ssl
import struct
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import certdiag.cli as cli
import certdiag.probe as P
from certdiag import report as R
from certdiag.pe import inspect as pe_inspect

CMD = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"


def build_pe(**kw) -> bytes:
    e_lfanew = kw.get("e_lfanew", 0x40)
    sig = kw.get("sig", b"PE\0\0")
    opt_size = kw.get("opt_size", 224)
    total = kw.get("total", 0x180)
    data = bytearray(total)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    if e_lfanew + 4 + 20 <= len(data):
        data[e_lfanew:e_lfanew + 4] = sig
        coff = e_lfanew + 4
        struct.pack_into("<HHIIIHH", data, coff, 0x14C, 1, 0, 0, 0, opt_size, 0x0102)
        opt = coff + 20
        if opt + 2 <= len(data):
            struct.pack_into("<H", data, opt, 0x10B)
        if opt + 132 <= len(data):
            # 安全目录（第 5 项，PE32 偏移 96+8*4）
            struct.pack_into("<II", data, opt + 128, kw.get("cert_off", 0), kw.get("cert_size", 0))
    return bytes(data)


class TestPeEdges(unittest.TestCase):
    def _inspect(self, data: bytes):
        f = Path(tempfile.mkdtemp()) / "x.exe"
        f.write_bytes(data)
        try:
            return pe_inspect(str(f))
        finally:
            f.unlink(missing_ok=True)

    def test_bad_pe_signature(self):
        out = self._inspect(build_pe(sig=b"PE\0\1"))
        self.assertFalse(out["is_pe"])
        self.assertIn("缺少 PE 签名", out["reason"])

    def test_truncated_optional_header(self):
        out = self._inspect(build_pe(total=0x40 + 4 + 20 + 1))
        self.assertTrue(out.get("truncated"))

    def test_truncated_data_directory(self):
        out = self._inspect(build_pe(opt_size=40))
        self.assertTrue(out.get("truncated"))
        self.assertIn("数据目录", out["reason"])

    def test_section_table_beyond_eof(self):
        # 节表起始在 0x138，文件截断到 0x140
        out = self._inspect(build_pe(total=0x140))
        self.assertTrue(out.get("truncated"))
        self.assertIn("节表", out["reason"])

    def test_cert_table_beyond_eof(self):
        out = self._inspect(build_pe(cert_off=0x1000, cert_size=0x100))
        self.assertTrue(out.get("truncated"))
        self.assertIn("证书表", out["reason"])

    def test_trailing_after_signature(self):
        out = self._inspect(build_pe(cert_off=0x100, cert_size=0x10))
        self.assertFalse(out.get("truncated"))
        self.assertEqual(out["cert_end"], 0x110)
        self.assertGreater(out["trailing_after_signature"], 0)

    def test_unreadable(self):
        with mock.patch("builtins.open", side_effect=OSError("denied")):
            out = pe_inspect(str(CMD))
        self.assertIn("无法读取", out["reason"])


class TestHttpBranches(unittest.TestCase):
    class _Opener:
        def __init__(self, exc):
            self.exc = exc

        def open(self, req, timeout=None):
            raise self.exc

    def _http(self, exc):
        with mock.patch.object(P, "_build_opener", return_value=self._Opener(exc)):
            return P._http("http://x/", 1)

    def test_http_error(self):
        code, tls, _ = self._http(urllib.error.HTTPError("u", 404, "nf", {}, None))
        self.assertEqual((code, tls), ("404", "ok"))

    def test_tls_error_in_urlerror(self):
        code, tls, _ = self._http(urllib.error.URLError(ssl.SSLError("bad")))
        self.assertEqual((code, tls), ("", "error"))

    def test_timeout_in_urlerror(self):
        code, tls, _ = self._http(urllib.error.URLError(socket.timeout("t")))
        self.assertEqual((code, tls), ("", "skip"))

    def test_generic_urlerror(self):
        code, tls, msg = self._http(urllib.error.URLError(OSError("boom")))
        self.assertEqual((code, tls), ("", "skip"))
        self.assertIn("HTTP 失败", msg)

    def test_direct_ssl_error(self):
        self.assertEqual(self._http(ssl.SSLError("bad"))[:2], ("", "error"))

    def test_direct_timeout(self):
        self.assertEqual(self._http(socket.timeout("t"))[:2], ("", "skip"))

    def test_other_exception(self):
        self.assertEqual(self._http(RuntimeError("x"))[:2], ("", "skip"))


class TestReportHelpers(unittest.TestCase):
    def test_signals_bad_hresult(self):
        s = R._signals({"status": "Valid", "hresult": "not-a-number"})
        self.assertIsNone(s["winverifytrust"])

    def test_signals_conflict(self):
        s = R._signals({"status": "Valid", "hresult": 0x800B0109})
        self.assertTrue(s["conflict"])

    def test_fmt_size(self):
        self.assertEqual(R._fmt_size(None), "-")
        self.assertEqual(R._fmt_size("x"), "-")
        self.assertIn("KB", R._fmt_size(2048))

    def test_cell(self):
        self.assertEqual(R._cell(None), "")
        self.assertIn("\\|", R._cell("a|b"))

    def test_markdown_offline_and_urls(self):
        base = {
            "file": {"path": "x", "size": 1, "sha256": "X"}, "signature": {"status": "Valid"},
            "diagnosis": {"verdict": "valid", "category": "valid", "cause": "c",
                          "confidence": "high", "advice": [], "evidence": []},
            "chain": {"elements": []}, "catalog": {}, "generated_at": "t", "offline": True,
            "revocation": {"urls": [], "probes": []}, "revocation_check": {},
        }
        md = R.render_markdown(base)
        self.assertIn("离线模式", md)

        base["offline"] = False
        base["revocation"] = {"urls": ["http://x/a.crl"], "probes": [
            {"url": "http://x/a.crl", "dns": "ok", "tcp": "ok", "http": "200",
             "category": "ok", "detail": "fine"}]}
        md = R.render_markdown(base)
        self.assertIn("共发现 1 个地址", md)

        base["revocation"] = {"urls": [], "probes": []}
        md = R.render_markdown(base)
        self.assertIn("未找到 CRL/OCSP 地址", md)

        base["revocation_check"] = {"mode": "off", "effective": "off", "checked": False,
                                    "state": "unchecked", "reason": "因为 --revoke=off"}
        md = R.render_markdown(base)
        self.assertIn("原因：因为 --revoke=off", md)

        base["collect_error"] = "采集炸了"
        self.assertIn("采集炸了", R.render_markdown(base))


class TestCliFilters(unittest.TestCase):
    def test_count_verdicts_unknown_key(self):
        counts = cli.count_verdicts([{"diagnosis": {"verdict": "weird"}},
                                     {"diagnosis": {}}, {}])
        self.assertEqual(counts["weird"], 1)
        self.assertEqual(counts["unknown"], 2)

    def test_fix_console_reconfigures(self):
        class S:
            encoding = "cp1252"
            def __init__(self):
                self.calls = []
            def reconfigure(self, **kw):
                self.calls.append(kw)
            def write(self, *a):
                pass
            def flush(self):
                pass

        out, err = S(), S()
        with mock.patch.object(cli.sys, "stdout", out), mock.patch.object(cli.sys, "stderr", err):
            cli.fix_console()
        self.assertTrue(out.calls and err.calls)


class TestRevocationPaths(unittest.TestCase):
    def setUp(self):
        import certdiag.collect as C
        self.real = C.collect
        self.C = C

    def _fake(self, behavior):
        def fake(p, revoke="NoCheck", **kw):
            if revoke in ("Online", "Offline"):
                return behavior()
            return self.real(p, revoke=revoke, **kw)
        return fake

    def test_exception_in_recheck(self):
        def boom():
            raise RuntimeError("kaboom")
        with mock.patch.object(cli, "collect", self._fake(boom)):
            rep = cli.diagnose_one(CMD, offline=False, no_probe=True, timeout=5,
                                   revoke_mode="online", revoke_timeout=5)
        self.assertIn("吊销复查异常", " ".join(rep["diagnosis"]["not_checked"]))

    def test_error_reason(self):
        with mock.patch.object(cli, "collect", self._fake(lambda: {"error": "boom"})):
            rep = cli.diagnose_one(CMD, offline=False, no_probe=True, timeout=5,
                                   revoke_mode="online", revoke_timeout=5)
        self.assertIn("boom", " ".join(rep["diagnosis"]["not_checked"]))

    def test_dual_signature_conflict(self):
        def fake(p, revoke="NoCheck", **kw):
            d = self.real(p, revoke=revoke, **kw)
            d = dict(d)
            d["status"] = "NotTrusted"
            d["hresult"] = 0x800B0109
            d["hresult_name"] = "CERT_E_UNTRUSTEDROOT"
            return d

        cat = {"found": True, "path": "x.cat", "signature_status": "Valid"}
        with mock.patch.object(cli, "collect", fake), \
             mock.patch.object(cli, "wv_verify",
                               return_value={"hresult": 0x800B0109,
                                             "name": "CERT_E_UNTRUSTEDROOT",
                                             "desc": "root"}):
            rep = cli.diagnose_one(CMD, offline=True, no_probe=True, timeout=5,
                                   force_catalog=True)
        # _catalog_info 会去查真实 catalog；这里只断言不崩且分类合理
        self.assertIn(rep["diagnosis"]["verdict"], ("invalid", "unknown"))

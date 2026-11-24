# -*- coding: utf-8 -*-
"""覆盖率补白：用 mock 触发"平时走不到"的分支（超时、注册表、旧接口、错误路径）。

这些分支不需要真实故障：它们的职责是"出错时给出正确分类"，
所以用替身制造故障，断言分类正确即可。
"""
from __future__ import annotations

import ctypes
import os
import socket
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import certdiag.probe as P
from certdiag import catalog as CAT
from certdiag import proxy as PROXY
from certdiag import timestamp as TS
from certdiag.attrib import DiagInput, diagnose

CMD = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"


class TestResolveBranches(unittest.TestCase):
    def test_timeout(self):
        with mock.patch.object(P.socket, "getaddrinfo",
                               side_effect=lambda *a, **k: __import__("time").sleep(0.5)):
            state, ips, msg = P._resolve("example.com", 0.05)
        self.assertEqual(state, "timeout")
        self.assertEqual(ips, [])

    def test_dns_error(self):
        with mock.patch.object(P.socket, "getaddrinfo", side_effect=OSError("boom")):
            state, _, msg = P._resolve("example.com", 1)
        self.assertEqual(state, "fail")
        self.assertIn("DNS 异常", msg)

    def test_gaierror(self):
        with mock.patch.object(P.socket, "getaddrinfo", side_effect=socket.gaierror("x")):
            state, _, msg = P._resolve("example.com", 1)
        self.assertEqual(state, "fail")
        self.assertIn("DNS 解析失败", msg)


class TestTcpBranches(unittest.TestCase):
    def test_timeout(self):
        with mock.patch.object(P.socket, "create_connection", side_effect=socket.timeout("t")):
            self.assertEqual(P._tcp("h", 1, 0.1)[0], "timeout")

    def test_refused(self):
        with mock.patch.object(P.socket, "create_connection", side_effect=ConnectionRefusedError()):
            self.assertEqual(P._tcp("h", 1, 0.1)[0], "refused")

    def test_unreachable(self):
        with mock.patch.object(P.socket, "create_connection", side_effect=OSError("no route")):
            state, msg = P._tcp("h", 1, 0.1)
        self.assertEqual(state, "unreachable")
        self.assertIn("不可达", msg)


class TestOpenerAndProxyHttp(unittest.TestCase):
    def setUp(self):
        P._opener_cache.clear()

    def tearDown(self):
        P._opener_cache.clear()

    def test_opener_with_proxy(self):
        info = PROXY.ProxyInfo(True, "http://127.0.0.1:9", "", "", "env")
        with mock.patch("certdiag.proxy.detect", return_value=info):
            op = P._build_opener()
        self.assertTrue(any(isinstance(h, __import__("urllib.request").request.ProxyHandler)
                            for h in op.handlers))

    def _probe(self, kind="crl"):
        return P.ProbeResult(url="http://x/a.crl", kind=kind)

    def test_via_proxy_ok(self):
        r = self._probe()
        with mock.patch.object(P, "_http", return_value=("200", "ok", "")):
            self.assertTrue(P._http_via_proxy(r.url, 1, r))
        self.assertEqual(r.category, "ok")

    def test_via_proxy_tls_error(self):
        r = self._probe()
        with mock.patch.object(P, "_http", return_value=("", "error", "cert")):
            self.assertTrue(P._http_via_proxy(r.url, 1, r))
        self.assertEqual(r.category, "tls_error")

    def test_via_proxy_http_error(self):
        r = self._probe()
        with mock.patch.object(P, "_http", return_value=("500", "ok", "")):
            self.assertTrue(P._http_via_proxy(r.url, 1, r))
        self.assertEqual(r.category, "http_error")

    def test_via_proxy_ocsp_inconclusive(self):
        r = self._probe("ocsp")
        with mock.patch.object(P, "_http", return_value=("", "skip", "")):
            self.assertTrue(P._http_via_proxy(r.url, 1, r))
        self.assertEqual(r.category, "inconclusive")

    def test_via_proxy_gives_up(self):
        r = self._probe()
        with mock.patch.object(P, "_http", return_value=("", "skip", "")):
            self.assertFalse(P._http_via_proxy(r.url, 1, r))

    def test_via_proxy_exception(self):
        r = self._probe()
        with mock.patch.object(P, "_http", side_effect=RuntimeError("x")):
            self.assertFalse(P._http_via_proxy(r.url, 1, r))


class TestProxyParsing(unittest.TestCase):
    def test_env_without_scheme(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "127.0.0.1:8080"}, clear=True):
            info = PROXY._from_env()
        self.assertEqual(info.server, "http://127.0.0.1:8080")
        self.assertTrue(info.enabled)

    def test_env_with_scheme(self):
        with mock.patch.dict(os.environ, {"ALL_PROXY": "socks5://127.0.0.1:1080"}, clear=True):
            self.assertEqual(PROXY._from_env().server, "socks5://127.0.0.1:1080")

    def test_env_empty(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(PROXY._from_env().enabled)

    def test_non_windows(self):
        with mock.patch.object(sys, "platform", "linux"):
            self.assertFalse(PROXY._from_ie().enabled)

    @unittest.skipUnless(sys.platform.startswith("win"), "注册表分支仅 Windows")
    def test_ie_registry(self):
        def qv(key, name):
            if name == "ProxyEnable":
                return (1, 0)
            if name == "ProxyServer":
                return ("http=10.0.0.1:1;https=10.0.0.2:2", 0)
            raise FileNotFoundError(name)

        import winreg
        with mock.patch.object(winreg, "OpenKey", return_value=object()), \
             mock.patch.object(winreg, "QueryValueEx", side_effect=qv), \
             mock.patch.object(winreg, "CloseKey", return_value=None):
            info = PROXY._from_ie()
        self.assertEqual(info.server, "http://10.0.0.2:2")
        self.assertEqual(info.source, "ie")

    @unittest.skipUnless(sys.platform.startswith("win"), "注册表分支仅 Windows")
    def test_ie_pac_only(self):
        def qv(key, name):
            if name == "ProxyEnable":
                return (0, 0)
            if name == "AutoConfigURL":
                return ("http://pac.local/proxy.pac", 0)
            raise FileNotFoundError(name)

        import winreg
        with mock.patch.object(winreg, "OpenKey", return_value=object()), \
             mock.patch.object(winreg, "QueryValueEx", side_effect=qv), \
             mock.patch.object(winreg, "CloseKey", return_value=None):
            info = PROXY._from_ie()
        self.assertFalse(info.enabled)
        self.assertEqual(info.auto_config, "http://pac.local/proxy.pac")
        self.assertEqual(info.source, "ie-pac")


@unittest.skipUnless(sys.platform.startswith("win"), "仅 Windows")
class TestCatalogBranches(unittest.TestCase):
    def test_has_missing_function(self):
        self.assertFalse(CAT._has("DefinitelyNotAWin32Function"))

    def test_find_missing_file(self):
        r = CAT.find_catalog("Z:/nope.exe")
        self.assertFalse(r.found)
        self.assertIn("不存在", r.get("error") or "")

    def test_open_failure(self):
        with mock.patch.object(CAT._kernel32, "CreateFileW",
                               return_value=CAT.INVALID_HANDLE_VALUE):
            r = CAT.find_catalog(str(CMD))
        self.assertFalse(r.found)
        self.assertIn("无法打开", r.get("error") or "")

    def test_acquire_failure(self):
        with mock.patch.object(CAT, "HAS_CTX2", False), \
             mock.patch.object(CAT._crypt32, "CryptCATAdminAcquireContext",
                               return_value=0):
            with self.assertRaises(OSError):
                CAT._acquire("SHA256")

    def test_hash_file_legacy(self):
        def calc(handle, size_ptr, buf, flags):
            size_ptr._obj.value = 4
            if buf:
                ctypes.memset(buf, 0x41, 4)
            return 1

        with mock.patch.object(CAT, "HAS_HASH2", False), \
             mock.patch.object(CAT._crypt32, "CryptCATAdminCalcHashFromFileHandle",
                               side_effect=calc):
            out = CAT._hash_file(object(), object(), None)
        self.assertEqual(out, b"AAAA")

    def test_hash_file_failure(self):
        with mock.patch.object(CAT, "HAS_HASH2", False), \
             mock.patch.object(CAT._crypt32, "CryptCATAdminCalcHashFromFileHandle",
                               return_value=0):
            with self.assertRaises(OSError):
                CAT._hash_file(object(), object(), None)


class TestTimestampBranches(unittest.TestCase):
    def setUp(self):
        import certdiag.collect as C
        self.C = C
        self._old = C._use_worker
        C._use_worker = False

    def tearDown(self):
        self.C._use_worker = self._old

    def test_missing_file(self):
        r = TS.verify("Z:/nope.exe")
        self.assertEqual(r.get("error"), "文件不存在")

    def test_powershell_fallback_to_pwsh(self):
        with mock.patch("shutil.which",
                        side_effect=lambda n: r"C:\pwsh.exe" if n.startswith("pwsh") else None):
            self.assertTrue(TS._powershell().endswith("pwsh.exe"))

    def test_no_powershell(self):
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(RuntimeError):
                TS._powershell()

    def test_verify_without_powershell(self):
        with mock.patch("shutil.which", return_value=None):
            r = TS.verify(str(CMD))
        self.assertIn("未找到 PowerShell", r.get("error") or "")

    def test_oversize_file(self):
        with mock.patch("os.path.getsize", return_value=TS.MAX_PARSE_BYTES + 1), \
             mock.patch("shutil.which", return_value=r"C:\pwsh.exe"):
            r = TS.verify(str(CMD))
        self.assertIn("文件过大", r.get("error") or "")

    def test_size_error(self):
        with mock.patch("os.path.getsize", side_effect=OSError("denied")), \
             mock.patch("shutil.which", return_value=r"C:\pwsh.exe"):
            r = TS.verify(str(CMD))
        self.assertIn("无法读取文件大小", r.get("error") or "")


class TestAttribBranches(unittest.TestCase):
    def test_corrupt_pe(self):
        d = diagnose(DiagInput(status="NotSigned",
                               pe={"is_pe": True, "truncated": True, "reason": "头部越界"}))
        self.assertEqual(d.category, "corrupt_pe")
        self.assertEqual(d.verdict, "unknown")

    def test_offline_revocation(self):
        d = diagnose(DiagInput(status="NotTrusted", chain_flags=["OfflineRevocation"],
                               offline=True))
        self.assertEqual(d.category, "revocation_not_checked")

    def test_revocation_unknown(self):
        d = diagnose(DiagInput(status="NotTrusted", chain_flags=["OfflineRevocation"],
                               offline=False))
        self.assertEqual(d.category, "revocation_unknown")


class TestExpandBranches(unittest.TestCase):
    def test_walk_stat_error(self):
        import certdiag.cli as cli
        real = os.stat
        d = Path(tempfile.mkdtemp())

        def fake(p, *a, **k):
            if str(p).startswith("C:/nope"):
                raise OSError("x")
            return real(p, *a, **k)

        with mock.patch.object(cli.os, "walk",
                               return_value=iter([("C:/nope", [], [])])), \
             mock.patch.object(cli.os, "stat", side_effect=fake):
            self.assertEqual(cli._expand([str(d)]), [])

    def test_walk_cycle_guard(self):
        import certdiag.cli as cli
        real = os.stat
        d = Path(tempfile.mkdtemp())

        def fake(p, *a, **k):
            if str(p).startswith("C:/loop"):
                return types.SimpleNamespace(st_dev=1, st_ino=1)
            return real(p, *a, **k)

        walk = iter([("C:/loop", [], ["a.exe"]), ("C:/loop/sub", [], ["b.exe"])])
        with mock.patch.object(cli.os, "walk", return_value=walk), \
             mock.patch.object(cli.os, "stat", side_effect=fake):
            names = [p.name for p in cli._expand([str(d)])]
        self.assertEqual(names, ["a.exe"])


class TestPsworkerScriptPath(unittest.TestCase):
    def test_new_script_path_is_unique(self):
        from certdiag.psworker import new_script_path, script_dir

        d = script_dir()
        a = new_script_path(d)
        b = new_script_path(d)
        self.assertNotEqual(a, b)
        self.assertTrue(a.endswith(".ps1"))
        Path(a).unlink(missing_ok=True)
        Path(b).unlink(missing_ok=True)

# -*- coding: utf-8 -*-
"""覆盖率补白（三）：worker 目录探测、UI 批量/上传、归因尾部分支、CLI 参数错误。"""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import certdiag.cli as cli
import certdiag.psworker as W
from certdiag.attrib import DiagInput, diagnose

CMD = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"


class TestPsworker(unittest.TestCase):
    def test_find_powershell_missing(self):
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(RuntimeError):
                W._find_powershell()

    def test_candidate_dirs_env(self):
        with mock.patch.dict(os.environ, {"CERTDIAG_TMP": r"C:\tmp\cd"}, clear=False):
            dirs = W._candidate_dirs()
        self.assertEqual(dirs[0], Path(r"C:\tmp\cd"))

    def test_worker_dir_fallback(self):
        with mock.patch.object(W, "_candidate_dirs", return_value=[Path("Z:/nope")]):
            d = W._worker_dir()
        self.assertEqual(d, Path(tempfile.gettempdir()))

    def test_new_script_retry_then_fail(self):
        with mock.patch("builtins.open", side_effect=FileExistsError):
            with self.assertRaises(RuntimeError):
                W._new_script_path(Path(tempfile.gettempdir()))

    def test_cleanup_stale(self):
        d = Path(tempfile.mkdtemp())
        old = d / "certdiag_worker_dead.ps1"
        old.write_text("x", encoding="utf-8")
        os.utime(old, (time.time() - 48 * 3600,) * 2)
        with mock.patch.object(W, "_candidate_dirs", return_value=[d]):
            W._cleanup_stale_scripts()
        self.assertFalse(old.exists())
        shutil.rmtree(d, ignore_errors=True)


class TestAttribTail(unittest.TestCase):
    def test_key_usage(self):
        d = diagnose(DiagInput(status="NotTrusted", chain_flags=["NotValidForUsage"]))
        self.assertEqual(d.category, "key_usage")
        self.assertEqual(d.verdict, "invalid")

    def test_expired_os_says_valid(self):
        d = diagnose(DiagInput(status="Valid", hresult=0, signer_expired=True))
        self.assertEqual(d.category, "expired_with_timestamp")
        self.assertEqual(d.verdict, "valid")
        self.assertEqual(d.confidence, "low")


class TestCliArgs(unittest.TestCase):
    def test_ui_branch(self):
        with mock.patch("certdiag.ui.serve", return_value=None) as srv:
            code = cli.main(["--ui", "--no-browser", "--port", "0"])
        self.assertEqual(code, 0)
        self.assertTrue(srv.called)

    def test_no_paths(self):
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main([])
        self.assertEqual(code, 3)

    def test_bad_revoke_mode(self):
        with self.assertRaises(SystemExit) as cm:
            with mock.patch("sys.stderr", io.StringIO()):
                cli.main([str(CMD), "--revoke", "definitely-not-a-mode"])
        self.assertEqual(cm.exception.code, 2)

    def test_fix_console_survives_failure(self):
        class Bad:
            encoding = "cp1252"
            def reconfigure(self, **kw):
                raise OSError("nope")
            def write(self, *a):
                pass
            def flush(self):
                pass

        with mock.patch.object(cli.sys, "stdout", Bad()), \
             mock.patch.object(cli.sys, "stderr", Bad()):
            cli.fix_console()          # 不应抛异常


@unittest.skipUnless(CMD.exists(), "需要 Windows 系统文件")
class TestUiBatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import threading
        from http.server import ThreadingHTTPServer

        from certdiag.ui import _Handler

        cls.dir = Path(tempfile.mkdtemp())
        shutil.copy2(CMD, cls.dir / "a.exe")
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def post(self, path, payload):
        import http.client

        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        c.request("POST", path, body=json.dumps(payload).encode(),
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def test_batch_stream(self):
        st, data = self.post("/api/batch", {"path": str(self.dir), "no_probe": True,
                                            "offline": True})
        self.assertEqual(st, 200)
        lines = [json.loads(x) for x in data.decode("utf-8").splitlines() if x.strip()]
        self.assertTrue(any(x.get("done") for x in lines))

    def test_export_md_full_report(self):
        rep = {
            "file": {"path": "x", "size": 1, "sha256": "X"},
            "signature": {"status": "Valid"},
            "diagnosis": {"verdict": "valid", "category": "valid", "cause": "c",
                          "confidence": "high", "advice": [], "evidence": []},
            "chain": {"elements": []}, "catalog": {},
            "revocation": {"urls": [], "probes": []}, "revocation_check": {},
            "offline": True, "generated_at": "t",
        }
        st, data = self.post("/api/export", {"report": rep, "fmt": "md"})
        self.assertEqual(st, 200)
        self.assertIn("# 证书诊断报告", data.decode("utf-8"))

    def test_upload_oversize(self):
        import http.client

        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("POST", "/api/upload", body=b"",
                  headers={"Content-Length": str(300 * 1024 * 1024)})
        r = c.getresponse()
        body = r.read()
        c.close()
        self.assertEqual(r.status, 200)
        self.assertIn("200 MB", json.loads(body)["error"])

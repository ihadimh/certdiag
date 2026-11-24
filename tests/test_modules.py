# -*- coding: utf-8 -*-
"""零散模块的覆盖：一次性时间戳、catalog/winverify 的说明函数、serve 的占用分支。"""
from __future__ import annotations

import os
import socket
import unittest
from pathlib import Path

CMD = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"


class TestDescribeHelpers(unittest.TestCase):
    def test_catalog_describe(self):
        from certdiag.catalog import describe

        self.assertIn("未找到", describe({}))
        self.assertIn("x.cat", describe({"catalog_path": r"C:\x.cat", "hash_alg": "SHA256"}))

    def test_winverify_explain(self):
        from certdiag.winverify import explain

        self.assertEqual(explain(None), "")
        self.assertIn("0x800B0109", explain(0x800B0109))
        self.assertIn("UNKNOWN", explain(0x12345678))


class TestCollectStats(unittest.TestCase):
    def test_stats_and_close(self):
        import certdiag.collect as C

        s = C.stats()
        self.assertIn("worker_calls", s)
        C.close()          # 没有 worker 时也应安全
        C.close()          # 幂等


@unittest.skipUnless(CMD.exists(), "需要 Windows 系统文件")
class TestTimestampOneShot(unittest.TestCase):
    """走"没有 worker"的一次性脚本路径（临时文件 + PowerShell -File）。"""

    def test_unsigned_file(self):
        import certdiag.collect as C
        from certdiag.timestamp import verify

        C._use_worker = False
        try:
            r = verify(str(CMD))
            self.assertFalse(r.get("has_signature"))
            self.assertFalse(r.get("token_ok"))
        finally:
            C._use_worker = True


class TestServePortInUse(unittest.TestCase):
    def test_existing_instance_branch(self):
        from certdiag.ui import serve

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.listen(1)
        try:
            import contextlib, io
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertIsNone(serve(port=port, open_browser=False, block=False))
        finally:
            s.close()

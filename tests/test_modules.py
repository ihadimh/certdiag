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


class TestOpenUrl(unittest.TestCase):
    """默认关联坏掉时（比如 Quark 被卸载），要能退回 Edge/Chrome。"""

    def test_prefers_edge(self):
        from unittest import mock

        from certdiag.ui import open_url

        with mock.patch("shutil.which", return_value=None), \
             mock.patch("os.path.exists", return_value=True), \
             mock.patch("subprocess.Popen") as popen:
            got = open_url("http://127.0.0.1:1/")
        self.assertTrue(got.endswith("msedge.exe"))
        self.assertEqual(popen.call_count, 1)

    def test_falls_back_to_default_browser(self):
        from unittest import mock

        import certdiag.ui as ui

        with mock.patch("shutil.which", return_value=None), \
             mock.patch("os.path.exists", return_value=False), \
             mock.patch.object(ui.threading, "Thread") as th:
            self.assertEqual(ui.open_url("http://127.0.0.1:1/"), "default")
        th.assert_called_once()


class TestOpenNotify(unittest.TestCase):
    def test_message_box_when_no_browser(self):
        from unittest import mock

        import certdiag.ui as ui

        with mock.patch.object(ui, "open_url"), \
             mock.patch.object(ui.time, "sleep"), \
             mock.patch.object(ui, "_browser_running", return_value=False), \
             mock.patch.object(ui, "_notify_url") as box:
            ui._open_and_notify("http://127.0.0.1:1/")
        box.assert_called_once()

    def test_no_message_box_when_browser_runs(self):
        from unittest import mock

        import certdiag.ui as ui

        with mock.patch.object(ui, "open_url"), \
             mock.patch.object(ui.time, "sleep"), \
             mock.patch.object(ui, "_browser_running", return_value=True), \
             mock.patch.object(ui, "_notify_url") as box:
            ui._open_and_notify("http://127.0.0.1:1/")
        box.assert_not_called()

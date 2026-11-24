# -*- coding: utf-8 -*-
"""审计回归测试：这些 bug 都真实发生过，不允许复发。"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestOriginParsing(unittest.TestCase):
    """Origin 解析曾经把"没写端口"当成任意端口，且畸形端口会抛异常。"""

    def test_cases(self):
        from certdiag.ui import origin_allowed

        ok = [
            ("http://127.0.0.1:8765", 8765),
            ("http://localhost:8765", 8765),
            ("", 8765),                       # 非浏览器客户端
        ]
        bad = [
            ("http://127.0.0.1", 8765),        # 默认 80，不是 8765
            ("http://127.0.0.1:9999", 8765),
            ("https://127.0.0.1:8765", 8765),
            ("http://127.0.0.1:8765.evil.com", 8765),   # 端口畸形，不能抛异常
            ("http://127.0.0.1.evil.com", 8765),
            ("null", 8765),
        ]
        for origin, port in ok:
            self.assertTrue(origin_allowed(origin, port), origin)
        for origin, port in bad:
            self.assertFalse(origin_allowed(origin, port), origin)


class TestHostAllowed(unittest.TestCase):
    def test_host_header(self):
        import certdiag.ui as ui

        class H:
            headers = {"Host": "evil.example"}
            _host_allowed = ui._Handler._host_allowed

        self.assertFalse(H()._host_allowed())

        H.headers = {"Host": "127.0.0.1:8765"}
        self.assertTrue(H()._host_allowed())


class TestMarkdownExport(unittest.TestCase):
    """--md 曾经因为变量名写错（out vs lines）直接 NameError。"""

    def _report(self):
        return {
            "file": {"path": "C:/x/a.exe", "size": 1, "sha256": "X"},
            "signature": {"status": "Valid", "signer": None},
            "diagnosis": {"verdict": "valid", "category": "valid", "cause": "ok",
                          "confidence": "high", "advice": [], "evidence": [],
                          "conflicts": [{"a": "x", "b": "y", "reason": "z"}],
                          "confidence_basis": "所有可用信号一致",
                          "not_checked": ["吊销状态"]},
            "chain": {"elements": []},
            "catalog": {},
            "revocation": {"urls": [], "probes": []},
            "revocation_check": {},
            "offline": True,
            "generated_at": "2026-01-01T00:00:00+08:00",
        }

    def test_conflicts_and_not_checked(self):
        from certdiag.report import render_markdown

        md = render_markdown(self._report())
        self.assertIn("冲突", md)
        self.assertIn("未验证", md)
        self.assertIn("置信度依据", md)


class TestExpandDirectory(unittest.TestCase):
    def test_only_pe_files(self):
        from certdiag.cli import _expand

        d = Path(tempfile.mkdtemp())
        (d / "a.txt").write_text("x")
        (d / "b.exe").write_bytes(b"MZ")
        names = [p.name for p in _expand([str(d)])]
        self.assertEqual(names, ["b.exe"])


@unittest.skipUnless(sys.platform == "win32", "仅 Windows")
class TestJsonWriteFailure(unittest.TestCase):
    """写不进报告文件时要给干净的错误，而不是 traceback。"""

    def test_unwritable_path(self):
        bad = "Z:\\nope\\r.json"
        r = subprocess.run(
            [sys.executable, "-m", "certdiag", r"C:\Windows\System32\cmd.exe", "--json", bad],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        self.assertEqual(r.returncode, 3, r.stderr[-300:])
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("无法写入", r.stderr)


if __name__ == "__main__":
    unittest.main()

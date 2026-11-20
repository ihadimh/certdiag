# -*- coding: utf-8 -*-
"""Windows 集成测试：这些是单元测试证明不了的部分。

CI 在 windows-latest 上跑；非 Windows 环境自动跳过。
"""
import sys
import unittest
from pathlib import Path

WINDOWS = sys.platform.startswith("win")
CMD = Path(r"C:\Windows\System32\cmd.exe")


@unittest.skipUnless(WINDOWS, "仅 Windows")
class TestWinVerifyTrust(unittest.TestCase):
    def test_ctypes_returns_hresult(self):
        from certdiag.winverify import verify

        r = verify(str(CMD))
        self.assertIsInstance(r.get("hresult"), int)
        # cmd.exe 没有嵌入式签名，WinVerifyTrust 只看文件自身
        self.assertEqual(r["name"], "TRUST_E_NOSIGNATURE")

    def test_codes_table_covers_core_errors(self):
        from certdiag.winverify import CODES

        # 断言名字，避免"数字在表里但含义错了"这种假通过
        expected = {
            0x800B0100: "TRUST_E_NOSIGNATURE",
            0x800B0109: "CERT_E_UNTRUSTEDROOT",
            0x800B010C: "CERT_E_REVOKED",
            0x800B010D: "CERT_E_UNTRUSTEDTESTROOT",
            0x80092013: "CRYPT_E_REVOCATION_OFFLINE",
        }
        for code, name in expected.items():
            self.assertIn(code, CODES)
            self.assertEqual(CODES[code][0], name, f"0x{code:08X} 名字错误")


@unittest.skipUnless(WINDOWS, "仅 Windows")
class TestCatalogApi(unittest.TestCase):
    def test_finds_catalog_for_system_file(self):
        from certdiag.catalog import find_catalog

        r = find_catalog(str(CMD))
        self.assertTrue(r.get("catalog_path"), f"未找到目录签名：{r.get('error')}")
        self.assertIn("catroot", r["catalog_path"].lower())
        self.assertIn(r.get("hash_alg"), ("SHA1", "SHA256"))

    def test_unsigned_temp_file_has_no_catalog(self):
        import tempfile

        from certdiag.catalog import find_catalog

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as fh:
            fh.write(b"not a signature\n")
            path = fh.name
        try:
            r = find_catalog(path)
            self.assertFalse(r.get("catalog_path"))
        finally:
            Path(path).unlink(missing_ok=True)


@unittest.skipUnless(WINDOWS, "仅 Windows")
class TestTimestampApi(unittest.TestCase):
    def test_file_without_embedded_signature(self):
        from certdiag.timestamp import verify

        r = verify(str(CMD))
        self.assertFalse(r.get("has_signature"))
        self.assertFalse(r.get("token_ok"))


if __name__ == "__main__":
    unittest.main()

@unittest.skipUnless(WINDOWS, "仅 Windows")
class TestCollectPaths(unittest.TestCase):
    """采集路径的回归：这两条路都曾经因为参数/属性问题整条挂掉。"""

    def test_oneshot_offline_succeeds(self):
        from certdiag.collect import _collect_subprocess

        r = _collect_subprocess(str(CMD), 60, "NoCheck", "true")
        self.assertIsNotNone(r.get("status"), f"一次性采集失败：{r.get('error')}")
        # PS 5.1 没有这个属性，应如实报 False 而不是抛异常
        self.assertIn("aia_downloads_disabled", r)

    def test_worker_offline_succeeds(self):
        from certdiag.psworker import PowerShellWorker

        w = PowerShellWorker()
        try:
            r = w.collect(str(CMD), 30, "NoCheck", True)
            self.assertIsNotNone(r.get("status"), f"worker 采集失败：{r.get('error')}")
            self.assertIn("aia_downloads_disabled", r)
        finally:
            w.close()


@unittest.skipUnless(WINDOWS, "仅 Windows")
class TestSignalsSummary(unittest.TestCase):
    def test_conflict_flagged_when_status_and_hresult_disagree(self):
        from certdiag.report import _signals

        s = _signals({"status": "Valid", "hresult": 0x80096011})
        self.assertTrue(s["conflict"])
        s2 = _signals({"status": "Valid", "hresult": 0})
        self.assertFalse(s2["conflict"])
        s3 = _signals({"status": "Valid", "hresult": 0x800B0100})
        self.assertFalse(s3["conflict"], "目录签名场景的正常返回不算冲突")


@unittest.skipUnless(WINDOWS, "仅 Windows")
class TestNonAsciiPath(unittest.TestCase):
    """中文/空格路径曾经被 worker 报成"文件不存在"（stdin 编码问题）。"""

    def test_chinese_and_space_path_via_worker(self):
        import shutil
        import tempfile
        from pathlib import Path as _P

        from certdiag.collect import PowerShellWorker

        tmp = _P(tempfile.mkdtemp()) / "中文 目录"
        tmp.mkdir()
        target = tmp / "中文 文件.exe"
        shutil.copy2(CMD, target)
        w = PowerShellWorker()
        try:
            r = w.collect(str(target), 30, "NoCheck", False)
            # 不能直接比字符串：CI 的 TEMP 是 8.3 短名（RUNNER~1），
            # PowerShell 返回的是长名，realpath 归一到同一形式再比
            import os as _os

            self.assertEqual(_os.path.normcase(_os.path.realpath(r.get("path") or "")),
                             _os.path.normcase(_os.path.realpath(str(target))))
            self.assertIsNotNone(r.get("status"), f"采集失败：{r.get('error')}")
        finally:
            w.close()
            shutil.rmtree(tmp.parent, ignore_errors=True)

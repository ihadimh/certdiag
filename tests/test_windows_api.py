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

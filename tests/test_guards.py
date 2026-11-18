# -*- coding: utf-8 -*-
"""证据采集层的护栏测试

这些不是"归因规则"测试，而是证明工具**不会把不可信输入当成可信依据**：
- 证书里的内网地址默认不探测（SSRF 面）
- Origin 不能用字符串前缀糊弄
- 目录签名要看 .cat 自身状态，不能只看到"找到了"
- --require-signature 门禁真的拦得住未签名文件
"""
import unittest

from certdiag.attrib import DiagInput, diagnose
from certdiag.cli import without_signature
from certdiag.probe import is_private_ip
from certdiag.ui import origin_allowed


class TestPrivateTargets(unittest.TestCase):
    def test_private_ranges_blocked(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1",
                   "169.254.1.1", "::1", "fe80::1"):
            self.assertTrue(is_private_ip(ip), ip)

    def test_public_addresses_allowed(self):
        for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
            self.assertFalse(is_private_ip(ip), ip)

    def test_garbage_is_treated_as_dangerous(self):
        self.assertTrue(is_private_ip("not-an-ip"))


class TestOriginAllowed(unittest.TestCase):
    def test_local_origins_pass(self):
        self.assertTrue(origin_allowed("http://127.0.0.1:8765", 8765))
        self.assertTrue(origin_allowed("http://localhost:8765", 8765))
        self.assertTrue(origin_allowed("", 8765))

    def test_prefix_trick_rejected(self):
        # startswith 写法会放过这个
        self.assertFalse(origin_allowed("http://localhost.attacker.example", 8765))

    def test_wrong_scheme_and_port_rejected(self):
        self.assertFalse(origin_allowed("https://127.0.0.1:8765", 8765))
        self.assertFalse(origin_allowed("http://127.0.0.1:9999", 8765))
        self.assertFalse(origin_allowed("http://evil.example", 8765))


class TestCatalogStatusMatters(unittest.TestCase):
    def _diag(self, status):
        return diagnose(DiagInput(
            status="Valid", hresult=0x800B0100,
            catalog={"found": True, "signature_status": status, "path": r"C:\x.cat"}))

    def test_valid_catalog_is_trust(self):
        d = self._diag("Valid")
        self.assertEqual(d.category, "catalog_only_trust")
        self.assertEqual(d.verdict, "valid")

    def test_hash_mismatch_catalog_is_invalid(self):
        d = self._diag("HashMismatch")
        self.assertEqual(d.category, "catalog_hash_mismatch")
        self.assertEqual(d.verdict, "invalid")

    def test_unknown_catalog_status_is_not_trust(self):
        for status in ("NotTrusted", "UnknownError", None):
            d = self._diag(status)
            self.assertEqual(d.category, "catalog_unverified", status)
            self.assertEqual(d.verdict, "unknown", status)


class TestSignatureGate(unittest.TestCase):
    def test_unsigned_is_flagged(self):
        reports = [{"diagnosis": {"category": "no_signature"}}]
        self.assertEqual(len(without_signature(reports)), 1)

    def test_signed_passes_gate(self):
        reports = [{"diagnosis": {"category": "valid_revocation_checked_ok"}}]
        self.assertEqual(without_signature(reports), [])

    def test_catalog_unverified_flagged(self):
        reports = [{"diagnosis": {"category": "catalog_unverified"}}]
        self.assertEqual(len(without_signature(reports)), 1)


class TestTimestampOids(unittest.TestCase):
    """嵌套签名 OID 不能被当成时间戳。"""

    def test_source_no_longer_treats_nested_signature_as_timestamp(self):
        from pathlib import Path

        src = Path(__file__).resolve().parent.parent / "certdiag" / "timestamp.py"
        lines = src.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if "311.2.4.1" not in line or line.strip().startswith("#"):
                continue
            # 命中 2.4.1 的那一行，紧接着必须把它归类为 nested signature 而不是继续走时间戳
            window = "\n".join(lines[i:i + 3])
            self.assertIn("has_nested_signature", window,
                          f"嵌套签名 OID 没有被排除：{line.strip()}")


if __name__ == "__main__":
    unittest.main()

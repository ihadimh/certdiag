# -*- coding: utf-8 -*-
"""证据采集层的护栏测试

这些不是"归因规则"测试，而是证明工具**不会把不可信输入当成可信依据**：
- 证书里的内网地址默认不探测（SSRF 面）
- Origin 不能用字符串前缀糊弄
- 目录签名要看 .cat 自身状态，不能只看到"找到了"
- --require-signature 门禁真的拦得住未签名文件
"""
import unittest
from pathlib import Path

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

class TestAuditFixes(unittest.TestCase):
    """2026-11-19 全量审计发现的问题，逐条钉住。"""

    def test_redirects_are_not_followed(self):
        # 跟随 302 可以绕过内网地址拦截
        from certdiag.probe import _NoRedirect

        h = _NoRedirect()
        self.assertIsNone(h.redirect_request(None, None, 302, "", {}, "http://127.0.0.1/"))

    def test_json_envelope_is_stable(self):
        # 单文件和多文件都必须是同一层结构，否则脚本消费会炸
        from certdiag.report import dump_json
        import json
        import tempfile

        payload = {"schema_version": 1, "tool": "certdiag",
                   "tool_version": "x", "count": 1, "reports": [{"a": 1}]}
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "r.json"
            dump_json(payload, str(out))
            data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(sorted(data), ["count", "reports", "schema_version", "tool", "tool_version"])

    def test_markdown_table_escapes_pipe(self):
        from certdiag.report import _cell

        self.assertEqual(_cell("a|b"), "a\\|b")
        self.assertEqual(_cell("a\nb"), "a b")

    def test_error_code_names_are_correct(self):
        from certdiag.attrib import HRESULT_MAP
        from certdiag.winverify import CODES

        self.assertEqual(HRESULT_MAP[0x800B010D][0], "CERT_E_UNTRUSTEDTESTROOT")
        self.assertEqual(HRESULT_MAP[0x80092013][0], "CRYPT_E_REVOCATION_OFFLINE")
        self.assertEqual(CODES[0x800B010D][0], "CERT_E_UNTRUSTEDTESTROOT")
        self.assertEqual(CODES[0x80092013][0], "CRYPT_E_REVOCATION_OFFLINE")

class TestPeInspection(unittest.TestCase):
    """损坏的 exe 不能被说成"这个类型没有签名"。"""

    def test_not_a_pe(self):
        from certdiag.pe import inspect
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "x.exe"
            f.write_bytes(b"hello world")
            self.assertFalse(inspect(str(f))["is_pe"])

    def test_truncated_pe_detected(self):
        import os
        import tempfile

        from certdiag.pe import inspect

        src = Path(__file__).resolve().parent.parent / "samples" / "signed_ok.exe"
        if not src.exists():
            self.skipTest("样本不存在")
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "t.exe"
            f.write_bytes(src.read_bytes()[:8192])
            r = inspect(str(f))
            self.assertTrue(r["is_pe"])
            self.assertTrue(r["truncated"])
            os.unlink(f)

    def test_bad_extension_name_check(self):
        from certdiag.pe import looks_like_pe_name

        self.assertTrue(looks_like_pe_name("a.EXE"))
        self.assertTrue(looks_like_pe_name("b.sys"))
        self.assertFalse(looks_like_pe_name("c.ps1"))

class TestConflictingHresult(unittest.TestCase):
    """状态说 Valid、WinVerifyTrust 却报错时，不能直接给 valid。"""

    def test_malformed_signature_is_unknown(self):
        d = diagnose(DiagInput(status="Valid", hresult=0x80096011))
        self.assertEqual(d.category, "malformed_signature")
        self.assertEqual(d.verdict, "unknown")

    def test_wrong_usage_is_invalid(self):
        d = diagnose(DiagInput(status="Valid", hresult=0x800B0110))
        self.assertEqual(d.category, "wrong_usage")
        self.assertEqual(d.verdict, "invalid")

    def test_unmapped_code_is_unknown_low_confidence(self):
        d = diagnose(DiagInput(status="Valid", hresult=0xDEADBEEF))
        self.assertEqual(d.category, "unexplained_hresult")
        self.assertEqual(d.verdict, "unknown")
        self.assertEqual(d.confidence, "low")

    def test_known_codes_still_work(self):
        # 0x800B0100 是目录签名场景的正常返回，不能被降级
        d = diagnose(DiagInput(status="Valid", hresult=0x800B0100,
                               catalog={"found": True, "signature_status": "Valid",
                                        "path": r"C:\x.cat"}))
        self.assertEqual(d.category, "catalog_only_trust")


class TestFetchMetadata(unittest.TestCase):
    """Sec-Fetch-Site 由浏览器强制发送，跨站请求不应被接受。"""

    def test_cross_site_rejected(self):
        import importlib
        import certdiag.ui as ui

        # 直接验证判定逻辑：构造一个最小的假 handler
        class H:
            headers = {"Host": "127.0.0.1:8765", "Sec-Fetch-Site": "cross-site"}
            server = type("S", (), {"server_address": ("127.0.0.1", 8765)})()

            _host_allowed = ui._Handler._host_allowed
            _trusted_caller = ui._Handler._trusted_caller

        self.assertFalse(H()._trusted_caller())

    def test_same_origin_accepted(self):
        import certdiag.ui as ui

        class H:
            headers = {"Host": "127.0.0.1:8765", "Sec-Fetch-Site": "same-origin"}
            server = type("S", (), {"server_address": ("127.0.0.1", 8765)})()

            _host_allowed = ui._Handler._host_allowed
            _trusted_caller = ui._Handler._trusted_caller

        self.assertTrue(H()._trusted_caller())

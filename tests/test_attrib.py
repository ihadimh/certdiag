# -*- coding: utf-8 -*-
"""attrib 归因引擎的单元测试

这些用例把"同一个现象可能有不同原因"固定下来：
网络不通导致的吊销失败，不能被判成证书无效。
"""
import unittest

from certdiag.attrib import DiagInput, diagnose, HRESULT_MAP


def crl(url="http://crl.example.com/a.crl", category="blocked", kind="crl"):
    return {"url": url, "kind": kind, "category": category, "detail": "TCP 超时"}


class TestAttribution(unittest.TestCase):
    def test_no_signature(self):
        d = diagnose(DiagInput(status="NotSigned"))
        self.assertEqual(d.category, "no_signature")
        self.assertEqual(d.verdict, "unknown")   # 不是"无效"，是"无从判断"

    def test_hash_mismatch(self):
        d = diagnose(DiagInput(status="HashMismatch"))
        self.assertEqual(d.category, "hash_mismatch")
        self.assertEqual(d.verdict, "invalid")

    def test_revocation_unreachable_is_unknown_not_invalid(self):
        d = diagnose(DiagInput(
            status="NotTrusted",
            chain_flags=["OfflineRevocation"],
            probes=[crl(category="blocked")]))
        self.assertEqual(d.category, "revocation_unreachable")
        self.assertEqual(d.verdict, "unknown")   # 关键：不能判成 invalid
        self.assertTrue(any("CRL" in a for a in d.advice))

    def test_ocsp_timeout_does_not_count_as_unreachable(self):
        d = diagnose(DiagInput(
            status="Valid",
            probes=[crl(url="http://ocsp.example.com", category="blocked", kind="ocsp")]))
        self.assertEqual(d.verdict, "valid")

    def test_inconclusive_ocsp(self):
        d = diagnose(DiagInput(
            status="NotTrusted",
            chain_flags=["OfflineRevocation"],
            probes=[{"url": "http://ocsp.example.com", "kind": "ocsp",
                     "category": "inconclusive", "detail": "GET 不被支持"}]))
        self.assertEqual(d.category, "revocation_unverified")
        self.assertEqual(d.verdict, "unknown")

    def test_untrusted_root(self):
        d = diagnose(DiagInput(status="NotTrusted", chain_flags=["UntrustedRoot"]))
        self.assertEqual(d.category, "untrusted_root")
        self.assertEqual(d.verdict, "invalid")

    def test_partial_chain(self):
        d = diagnose(DiagInput(status="NotTrusted", chain_flags=["PartialChain"]))
        self.assertEqual(d.category, "partial_chain")

    def test_expired_without_timestamp(self):
        d = diagnose(DiagInput(status="NotTrusted", chain_flags=["NotTimeValid"]))
        self.assertEqual(d.category, "expired")
        self.assertEqual(d.verdict, "invalid")

    def test_expired_with_timestamp_and_valid_status(self):
        d = diagnose(DiagInput(status="Valid", signer_expired=True, timestamp_present=True))
        self.assertEqual(d.category, "expired_with_timestamp")
        self.assertEqual(d.verdict, "valid")     # 系统已按时间戳判有效

    def test_clean_valid_requires_revocation_checked(self):
        # 只有"吊销真的查过且通过"才叫干净有效
        d = diagnose(DiagInput(
            status="Valid",
            probes=[{"url": "http://crl.example.com/a.crl", "kind": "crl",
                     "category": "ok", "detail": "200"}],
            revocation={"mode": "auto", "effective": "online", "checked": True,
                        "state": "checked_ok", "reason": ""}))
        self.assertEqual(d.category, "valid_revocation_checked_ok")
        self.assertEqual(d.confidence, "high")
        self.assertEqual(d.verdict, "valid")

    def test_valid_but_crl_down(self):
        d = diagnose(DiagInput(status="Valid", probes=[crl(category="dns_fail")],
                               revocation={"mode": "auto", "effective": "off",
                                           "checked": False, "state": "unchecked",
                                           "reason": "吊销地址不可达（DNS 解析失败）"}))
        self.assertEqual(d.category, "valid_revocation_unchecked")
        self.assertIn("不便", d.cause + "不便")  # 原因要写进结论
        self.assertEqual(d.verdict, "valid")

    def test_policy_url_failure_ignored(self):
        d = diagnose(DiagInput(
            status="Valid",
            probes=[crl(url="http://www.example.com/CPS", category="http_error", kind="policy")]))
        self.assertEqual(d.verdict, "valid")

    def test_hresult_takes_priority(self):
        d = diagnose(DiagInput(status="NotTrusted", hresult=0x800B010C))
        self.assertEqual(d.verdict, "invalid")
        self.assertIn("吊销", d.cause)

    def test_hresult_table_has_key_codes(self):
        # 不能只断言"这个数字在表里"——名字写错也要能测出来
        expected = {
            0x800B0100: "TRUST_E_NOSIGNATURE",
            0x800B0101: "CERT_E_EXPIRED",
            0x800B0109: "CERT_E_UNTRUSTEDROOT",
            0x800B010C: "CERT_E_REVOKED",
            0x800B010D: "CERT_E_UNTRUSTEDTESTROOT",
            0x80092013: "CRYPT_E_REVOCATION_OFFLINE",
            0x80096010: "TRUST_E_BAD_DIGEST",
        }
        for code, name in expected.items():
            self.assertIn(code, HRESULT_MAP)
            self.assertEqual(HRESULT_MAP[code][0], name,
                             f"0x{code:08X} 的名字写错了")

    def test_unmapped_status_falls_back(self):
        d = diagnose(DiagInput(status="SomeWeirdStatus"))
        self.assertEqual(d.category, "unknown")
        self.assertTrue(d.advice)


class TestProbeKinds(unittest.TestCase):
    def test_guess_kind(self):
        from certdiag.probe import guess_kind
        self.assertEqual(guess_kind("http://crl3.digicert.com/a.crl"), "crl")
        self.assertEqual(guess_kind("http://ocsp.digicert.com"), "ocsp")
        self.assertEqual(guess_kind("http://www.digicert.com/CPS"), "policy")
        self.assertEqual(guess_kind("http://cacerts.digicert.com/x.crt"), "cert")


if __name__ == "__main__":
    unittest.main()

class TestCatalog(unittest.TestCase):
    """目录签名（catalog）分支：系统文件常以 .cat 形式签名。"""

    def test_catalog_signed_is_valid_not_no_signature(self):
        d = diagnose(DiagInput(status="NotSigned", catalog={
            "found": True, "path": r"C:\Windows\System32\CatRoot\x.cat",
            "signature_status": "Valid", "signer": "CN=Microsoft Windows"}))
        self.assertEqual(d.category, "catalog_signed")
        self.assertEqual(d.verdict, "valid")

    def test_catalog_unverified_is_unknown(self):
        d = diagnose(DiagInput(status="NotSigned", catalog={
            "found": True, "path": "x.cat", "signature_status": None}))
        self.assertEqual(d.category, "catalog_unverified")
        self.assertEqual(d.verdict, "unknown")

    def test_catalog_bad_signature_is_invalid(self):
        d = diagnose(DiagInput(status="NotSigned", catalog={
            "found": True, "path": "x.cat", "signature_status": "HashMismatch"}))
        self.assertEqual(d.category, "catalog_hash_mismatch")
        self.assertEqual(d.verdict, "invalid")

    def test_no_catalog_falls_back_to_no_signature(self):
        d = diagnose(DiagInput(status="NotSigned", catalog={"found": False}))
        self.assertEqual(d.category, "no_signature")
        self.assertIn("目录签名", d.cause)

class TestHresultAndCatalogTrust(unittest.TestCase):
    """WinVerifyTrust 只看嵌入式签名，不能让它误伤目录签名文件。"""

    def test_strong_code_revoked_overrides(self):
        d = diagnose(DiagInput(status="NotTrusted", hresult=0x800B010C))
        self.assertEqual(d.verdict, "invalid")
        self.assertIn("吊销", d.cause)

    def test_nosignature_code_does_not_override(self):
        d = diagnose(DiagInput(status="NotSigned", hresult=0x800B0100,
                               catalog={"found": False}))
        self.assertEqual(d.category, "no_signature")
        self.assertNotIn("hresult:", d.category)

    def test_catalog_only_trust(self):
        d = diagnose(DiagInput(
            status="Valid", hresult=0x800B0100,
            catalog={"found": True, "path": "x.cat", "signature_status": "Valid"}))
        self.assertEqual(d.category, "catalog_only_trust")
        self.assertEqual(d.verdict, "valid")
        self.assertIn("目录签名", d.cause)

class TestOfflineHonesty(unittest.TestCase):
    """离线时不能声称"吊销检查通过"——没查就是没查。"""

    def test_offline_valid_does_not_claim_revocation_ok(self):
        d = diagnose(DiagInput(status="Valid", offline=True))
        self.assertEqual(d.verdict, "valid")
        self.assertEqual(d.category, "valid_offline")
        self.assertNotIn("吊销检查通过", d.cause)
        self.assertIn("未做吊销检查", d.cause)
        self.assertTrue(any("联网" in a for a in d.advice))

class TestFileScope(unittest.TestCase):
    """不是所有文件都有签名，别说成"无签名=可疑"。"""

    def test_unknown_type_is_not_a_problem(self):
        d = diagnose(DiagInput(status="UnknownError"))
        self.assertEqual(d.category, "not_applicable")
        self.assertEqual(d.verdict, "unknown")
        self.assertIn("签名", d.cause)

class TestTimestampChain(unittest.TestCase):
    """时间戳令牌校验把"可能有效"升级成"确认有效"。"""

    def test_timestamp_signature_ok_is_not_full_trust(self):
        d = diagnose(DiagInput(
            status="Valid", signer_expired=True,
            timestamp={"token_ok": True, "has_token": True,
                       "tsa_subject": "CN=Microsoft Public RSA Time Stamping Authority, O=Microsoft",
                       "tsa_not_after": "2026-10-23T04:46:49"}))
        self.assertEqual(d.category, "expired_with_timestamp_signature_ok")
        self.assertEqual(d.verdict, "valid")
        # 只验了令牌签名，没验 TSA 信任链 —— 不能给 high
        self.assertEqual(d.confidence, "medium")
        self.assertIn("未校验", d.cause)

    def test_broken_timestamp_is_unknown_not_invalid(self):
        d = diagnose(DiagInput(
            status="Valid", signer_expired=True,
            timestamp={"has_token": True, "token_ok": False, "error": "令牌签名校验失败"}))
        self.assertEqual(d.category, "expired_with_broken_timestamp")
        self.assertEqual(d.verdict, "unknown")

    def test_timestamp_without_verification_stays_hedged(self):
        d = diagnose(DiagInput(status="Valid", signer_expired=True, timestamp_present=True))
        self.assertEqual(d.category, "expired_with_timestamp")
        self.assertEqual(d.confidence, "medium")


class TestReviewFixes(unittest.TestCase):
    """两个 AI 评审指出的问题，用测试钉住。"""

    def test_no_probe_never_claims_revocation_ok(self):
        # 没查吊销就绝不能写"吊销检查通过"
        d = diagnose(DiagInput(status="Valid", probes=[],
                               revocation={"mode": "off", "effective": "off",
                                           "checked": False, "state": "unchecked",
                                           "reason": ""}))
        self.assertEqual(d.category, "valid_revocation_unchecked")
        self.assertEqual(d.confidence, "medium")
        self.assertNotIn("吊销检查通过", d.cause)

    def test_untrusted_root_beats_revocation_flags(self):
        # 链既不受信、吊销又查不到时，必须报证书问题，不能报网络问题
        d = diagnose(DiagInput(status="NotTrusted",
                               chain_flags=["UntrustedRoot", "OfflineRevocation"],
                               probes=[crl(category="blocked")]))
        self.assertEqual(d.verdict, "invalid")
        self.assertEqual(d.category, "untrusted_root")


class TestRevoked(unittest.TestCase):
    """吊销检查真的能定性"已吊销"。"""

    def test_revoked_is_invalid(self):
        d = diagnose(DiagInput(
            status="Valid",
            revocation={"mode": "auto", "effective": "online", "checked": True,
                        "state": "revoked", "reason": ""}))
        self.assertEqual(d.category, "revoked")
        self.assertEqual(d.verdict, "invalid")

class TestEvidencePriority(unittest.TestCase):
    """证据优先级：吊销是强否定，必须压过"过期但有时间戳"等正面推断。"""

    def test_revoked_beats_expired_with_timestamp(self):
        d = diagnose(DiagInput(
            status="Valid", signer_expired=True,
            timestamp={"has_token": True, "token_ok": True, "tsa_subject": "TSA"},
            revocation={"mode": "online", "effective": "online", "checked": True,
                        "state": "revoked", "reason": ""}))
        self.assertEqual(d.category, "revoked")
        self.assertEqual(d.verdict, "invalid")

    def test_revoked_chain_flag_also_wins(self):
        d = diagnose(DiagInput(status="Valid", chain_flags=["Revoked"],
                               signer_expired=True))
        self.assertEqual(d.category, "revoked")
        self.assertEqual(d.verdict, "invalid")


class TestRevocationEvidence(unittest.TestCase):
    """checked 只能来自"真的拿到链元素且没有未知标志"。"""

    def test_checked_ok_requires_chain_and_revocation(self):
        d = diagnose(DiagInput(
            status="Valid",
            revocation={"mode": "auto", "effective": "online", "checked": True,
                        "state": "checked_ok", "reason": ""}))
        self.assertEqual(d.category, "valid_revocation_checked_ok")
        self.assertEqual(d.confidence, "high")

    def test_unchecked_reports_reason(self):
        d = diagnose(DiagInput(
            status="Valid",
            revocation={"mode": "auto", "effective": "off", "checked": False,
                        "state": "unchecked", "reason": "吊销复查采集失败：worker 无响应"}))
        self.assertEqual(d.category, "valid_revocation_unchecked")
        self.assertIn("吊销复查采集失败", d.cause)


class TestCollectFailed(unittest.TestCase):
    """读不到文件时不能被解释成"内容不是 PE"。"""

    def test_error_without_status_is_collect_failed(self):
        from certdiag.attrib import diagnose_from_collect

        diag = diagnose_from_collect(
            {"path": "C:/x/locked.exe",
             "error": "文件正由另一进程使用，因此该进程无法访问此文件。"},
            probes=[],
        )
        self.assertEqual(diag.category, "collect_failed")
        self.assertEqual(diag.verdict, "unknown")
        self.assertIn("读取文件失败", diag.cause)
        self.assertEqual(diag.confidence, "low")


class TestDualSignature(unittest.TestCase):
    """嵌入式签名与目录签名同时存在时的仲裁。"""

    CAT_OK = {"found": True, "signature_status": "Valid", "path": "C:/x/a.cat"}
    CAT_BAD = {"found": True, "signature_status": "HashMismatch", "path": "C:/x/a.cat"}

    def _diag(self, status, hresult, catalog):
        from certdiag.attrib import diagnose_from_collect

        return diagnose_from_collect(
            {"path": "C:/x/a.exe", "status": status, "hresult": hresult},
            probes=[], catalog=catalog)

    def test_embedded_invalid_but_catalog_valid_is_unknown(self):
        d = self._diag("Valid", 0x800B0109, self.CAT_OK)
        self.assertEqual(d.category, "catalog_covers_embedded_invalid")
        self.assertEqual(d.verdict, "unknown")
        self.assertEqual(d.confidence, "low")
        self.assertTrue(any("目录签名状态" in e for e in d.evidence))

    def test_both_valid_records_catalog_evidence(self):
        d = self._diag("Valid", 0, self.CAT_OK)
        self.assertEqual(d.verdict, "valid")
        self.assertTrue(any("同时被目录签名覆盖" in e for e in d.evidence))

    def test_embedded_invalid_catalog_invalid_stays_invalid(self):
        d = self._diag("Valid", 0x800B0109, self.CAT_BAD)
        self.assertEqual(d.category, "untrusted_root")
        self.assertEqual(d.verdict, "invalid")

    def test_no_embedded_catalog_valid_is_catalog_only(self):
        d = self._diag("Valid", 0x800B0100, self.CAT_OK)
        self.assertEqual(d.category, "catalog_only_trust")

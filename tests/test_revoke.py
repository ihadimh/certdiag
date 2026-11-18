# -*- coding: utf-8 -*-
"""吊销检查策略的测试

关键不变量：off 档绝不能产出「检查通过」；auto 档在地址不可达时必须退化并说明原因。
"""
import unittest

from certdiag.revoke import (DESCRIPTION, MODES, RevokePolicyError, check_conflicts,
                             decide, label, normalize, summarize)


def probe(category="ok", kind="crl", detail=""):
    return {"category": category, "kind": kind, "detail": detail, "url": "http://x"}


class TestNormalize(unittest.TestCase):
    def test_all_modes(self):
        for m in MODES:
            self.assertEqual(normalize(m), m)

    def test_case_and_space(self):
        self.assertEqual(normalize(" CACHE "), "cache")

    def test_default_is_off(self):
        self.assertEqual(normalize(None), "off")

    def test_unknown_mode_raises(self):
        with self.assertRaises(RevokePolicyError):
            normalize("yes")


class TestConflicts(unittest.TestCase):
    def test_offline_with_online_raises(self):
        with self.assertRaises(RevokePolicyError):
            check_conflicts("online", offline=True)

    def test_offline_with_auto_raises(self):
        with self.assertRaises(RevokePolicyError):
            check_conflicts("auto", offline=True)

    def test_offline_with_cache_is_ok(self):
        check_conflicts("cache", offline=True)

    def test_offline_with_off_is_ok(self):
        check_conflicts("off", offline=True)


class TestDecide(unittest.TestCase):
    def test_non_auto_passthrough(self):
        self.assertEqual(decide("off", [probe()]), ("off", ""))
        self.assertEqual(decide("cache", [probe()]), ("cache", ""))
        self.assertEqual(decide("online", [probe()]), ("online", ""))

    def test_auto_with_reachable_target(self):
        eff, reason = decide("auto", [probe("ok"), probe("blocked")])
        self.assertEqual(eff, "online")
        self.assertEqual(reason, "")

    def test_auto_all_blocked_degrades_and_explains(self):
        eff, reason = decide("auto", [probe("blocked", detail="TCP 超时")])
        self.assertEqual(eff, "off")
        self.assertIn("不可达", reason)

    def test_auto_without_targets(self):
        eff, reason = decide("auto", [])
        self.assertEqual(eff, "off")
        self.assertIn("CRL/OCSP", reason)

    def test_policy_urls_do_not_count(self):
        # 只有 cps/policy 类地址时不应认为有吊销目标
        eff, reason = decide("auto", [probe("ok", kind="policy")])
        self.assertEqual(eff, "off")


class TestSummarize(unittest.TestCase):
    def test_revoked_wins(self):
        rev = summarize("auto", "online", checked=True, revoked=True, reason="")
        self.assertEqual(rev["state"], "revoked")

    def test_checked_ok(self):
        rev = summarize("cache", "cache", checked=True, revoked=False, reason="")
        self.assertEqual(rev["state"], "checked_ok")

    def test_unchecked_with_reason(self):
        rev = summarize("auto", "off", checked=False, revoked=False,
                        reason="吊销地址不可达（TCP 超时）")
        self.assertEqual(rev["state"], "unchecked")
        self.assertIn("不可达", rev["reason"])


class TestLabel(unittest.TestCase):
    def test_labels_never_say_passed_when_unchecked(self):
        rev = summarize("off", "off", checked=False, revoked=False, reason="")
        self.assertNotIn("通过", label(rev))
        self.assertIn("未检查", label(rev))

    def test_checked_label(self):
        rev = summarize("auto", "online", checked=True, revoked=False, reason="")
        self.assertIn("已检查", label(rev))

    def test_revoked_label(self):
        rev = summarize("auto", "online", checked=True, revoked=True, reason="")
        self.assertIn("已吊销", label(rev))

    def test_description_covers_all_modes(self):
        self.assertEqual(set(DESCRIPTION), set(MODES))


if __name__ == "__main__":
    unittest.main()

# -*- coding: utf-8 -*-
"""证据层：冲突检测、置信度推导、未检查项。"""
import unittest

from certdiag.evidence import (adjust_confidence, collect_signals, find_conflicts,
                               not_checked)


def base(**kw):
    d = {"status": "Valid", "hresult": 0, "pe": {"is_pe": True, "truncated": False,
                                                 "trailing_after_signature": 0}}
    d.update(kw)
    return d


class TestConflicts(unittest.TestCase):
    def test_status_valid_vs_winverifytrust_error(self):
        c = base(hresult=0x80096011, hresult_name="TRUST_E_MALFORMED_SIGNATURE")
        self.assertEqual(len(find_conflicts(collect_signals(c), c)), 1)

    def test_normal_case_has_no_conflict(self):
        c = base()
        self.assertEqual(find_conflicts(collect_signals(c), c), [])

    def test_catalog_return_is_not_conflict(self):
        # 目录签名场景 WinVerifyTrust 正常返回 0x800B0100，不算矛盾
        c = base(hresult=0x800B0100)
        self.assertEqual(find_conflicts(collect_signals(c), c), [])

    def test_truncated_pe_conflicts_with_valid(self):
        c = base(pe={"is_pe": True, "truncated": True})
        self.assertEqual(len(find_conflicts(collect_signals(c), c)), 1)

    def test_non_pe_conflicts_with_valid(self):
        c = base(pe={"is_pe": False, "truncated": False, "reason": "没有 MZ 头"})
        self.assertEqual(len(find_conflicts(collect_signals(c), c)), 1)


class TestNotChecked(unittest.TestCase):
    def test_revocation_off_is_listed(self):
        rev = {"mode": "off", "effective": "off", "state": "unchecked", "reason": ""}
        out = not_checked(base(), revocation=rev)
        self.assertTrue(any("吊销" in m for m in out))

    def test_catalog_member_only_when_catalog_used(self):
        out_no = not_checked(base(), catalog={"found": False})
        self.assertFalse(any("成员校验" in m for m in out_no))
        out_yes = not_checked(base(), catalog={"found": True})
        self.assertTrue(any("成员校验" in m for m in out_yes))


class TestConfidence(unittest.TestCase):
    def test_conflict_forces_low(self):
        level, basis = adjust_confidence("high", [{"a": 1}], [])
        self.assertEqual(level, "low")
        self.assertIn("冲突", basis)

    def test_collect_failure_limits_to_medium(self):
        level, basis = adjust_confidence("high", [], ["全部签名信息（采集失败）"])
        self.assertEqual(level, "medium")

    def test_no_change_without_conflict(self):
        level, basis = adjust_confidence("high", [], ["吊销状态（档位 off）"])
        self.assertEqual(level, "high")
        self.assertIn("一致", basis)

    def test_never_upgrades(self):
        level, _ = adjust_confidence("low", [], [])
        self.assertEqual(level, "low")

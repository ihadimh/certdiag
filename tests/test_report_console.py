# -*- coding: utf-8 -*-
"""控制台渲染的分支覆盖（这块曾经整段没测，导致建议被截断都没发现）。"""
from __future__ import annotations

import unittest

from certdiag.report import render_console


def make_report(**over):
    report = {
        "file": {"path": "C:/x/a.exe", "size": 1, "sha256": "X"},
        "signature": {"status": "Valid", "status_message": "", "signer": None},
        "diagnosis": {"verdict": "valid", "category": "valid", "cause": "一切正常",
                      "confidence": "high", "advice": [], "evidence": [],
                      "conflicts": [], "confidence_basis": "", "not_checked": []},
        "chain": {"elements": []},
        "catalog": {},
        "revocation": {"urls": [], "probes": []},
        "revocation_check": {},
        "offline": True,
        "generated_at": "2026-01-01T00:00:00+08:00",
    }
    report.update(over)
    return report


class TestVerdicts(unittest.TestCase):
    def test_three_verdicts(self):
        for verdict, mark in (("valid", "✅"), ("invalid", "❌"), ("unknown", "⚠️")):
            r = make_report()
            r["diagnosis"]["verdict"] = verdict
            self.assertIn(mark, render_console(r))

    def test_status_message_appended(self):
        r = make_report()
        r["signature"]["status_message"] = "系统说明"
        self.assertIn("（系统说明）", render_console(r))


class TestDiagnosisLines(unittest.TestCase):
    def test_conflicts_and_basis_and_missing(self):
        r = make_report()
        r["diagnosis"]["conflicts"] = [{"a": "A", "b": "B", "reason": "R"}]
        r["diagnosis"]["confidence_basis"] = "依据说明"
        r["diagnosis"]["not_checked"] = ["吊销状态", "时间戳"]
        text = render_console(r)
        self.assertIn("冲突：A vs B —— R", text)
        self.assertIn("置信度依据：依据说明", text)
        self.assertIn("未验证：吊销状态；时间戳", text)

    def test_advice_not_truncated(self):
        r = make_report()
        r["diagnosis"]["advice"] = ["第一条", "第二条", "第三条"]
        text = render_console(r)
        for item in ("第一条", "第二条", "第三条"):
            self.assertIn(item, text)


class TestCatalogAndProbes(unittest.TestCase):
    def test_catalog_line(self):
        r = make_report()
        r["catalog"] = {"found": True, "path": r"C:\Windows\CatRoot\x.cat",
                        "signature_status": "Valid"}
        self.assertIn("目录签名：x.cat（Valid）", render_console(r))

    def test_probes_all_ok(self):
        r = make_report()
        r["revocation"]["probes"] = [{"category": "ok"}, {"category": "ok"}]
        self.assertIn("吊销查询：2/2 个地址可达", render_console(r))

    def test_probes_with_inconclusive(self):
        r = make_report()
        r["revocation"]["probes"] = [{"category": "ok"},
                                     {"category": "inconclusive", "kind": "ocsp"}]
        text = render_console(r)
        self.assertIn("1 个 OCSP 端点无法用 GET 判定", text)

    def test_probes_unreachable(self):
        r = make_report()
        r["revocation"]["probes"] = [{"category": "ok"}, {"category": "blocked"}]
        self.assertIn("1 个地址不可达", render_console(r))

    def test_revocation_label(self):
        r = make_report()
        r["revocation_check"] = {"mode": "off", "effective": "off", "checked": False,
                                 "state": "unchecked", "reason": "--revoke=off"}
        self.assertIn("吊销", render_console(r))


class TestMinimal(unittest.TestCase):
    def test_missing_optional_sections(self):
        r = {"file": {"path": "x"}, "signature": {"status": "NotSigned"},
             "diagnosis": {"verdict": "unknown", "category": "no_signature",
                           "cause": "没签名", "confidence": "low"}}
        text = render_console(r)
        self.assertIn("没签名", text)
        self.assertNotIn("目录签名", text)

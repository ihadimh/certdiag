# -*- coding: utf-8 -*-
"""SARIF 输出与公共 API（attribute）的测试。"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from certdiag.sarif import build_sarif

CMD = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"


def _report(verdict, category, cause="原因", confidence="high", path="C:/x/a.exe", **extra):
    rep = {
        "file": {"path": path},
        "signature": extra.pop("signature", {}),
        "diagnosis": {"verdict": verdict, "category": category, "cause": cause,
                      "confidence": confidence,
                      "not_checked": extra.pop("not_checked", [])},
    }
    rep.update(extra)
    return rep


class TestSarif(unittest.TestCase):
    def test_invalid_and_unknown_only(self):
        reports = [
            _report("invalid", "hresult:TRUST_E_BAD_DIGEST", "哈希不匹配",
                    signature={"hresult": 0x80096010}),
            _report("unknown", "revocation_unverified", "吊销状态未知",
                    confidence="medium", not_checked=["吊销状态"]),
            _report("valid", "valid", "正常"),
        ]
        doc = build_sarif(reports, "2.4.0")
        run = doc["runs"][0]
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(run["tool"]["driver"]["version"], "2.4.0")
        self.assertEqual(len(run["results"]), 2)
        self.assertEqual({x["level"] for x in run["results"]}, {"error", "warning"})
        self.assertEqual({x["ruleId"] for x in run["results"]},
                         {"hresult:TRUST_E_BAD_DIGEST", "revocation_unverified"})
        bad = next(x for x in run["results"] if x["ruleId"].startswith("hresult:"))
        self.assertEqual(bad["properties"]["hresult"], "0x80096010")
        self.assertEqual(bad["properties"]["confidence"], "high")

    def test_chinese_path_is_uri_encoded(self):
        doc = build_sarif([_report("invalid", "untrusted_root", path="C:/证书/测试.exe")], "2.4.0")
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertTrue(uri.startswith("file:///"))
        self.assertIn("%E8%AF%81%E4%B9%A6", uri.upper())

    def test_empty(self):
        doc = build_sarif([], "2.4.0")
        self.assertEqual(doc["runs"][0]["results"], [])


@unittest.skipUnless(CMD.exists(), "需要 Windows 系统文件")
class TestAttribute(unittest.TestCase):
    def test_offline_report(self):
        from certdiag import attribute

        rep = attribute(CMD, offline=True)
        self.assertIn("diagnosis", rep)
        self.assertTrue(rep["file"]["path"].lower().endswith("cmd.exe"))
        self.assertIn(rep["diagnosis"]["verdict"], ("valid", "invalid", "unknown"))

    def test_missing_file(self):
        from certdiag import attribute

        rep = attribute("Z:/definitely-missing.exe", offline=True)
        self.assertEqual(rep["diagnosis"]["category"], "collect_failed")
        self.assertEqual(rep["diagnosis"]["verdict"], "unknown")


@unittest.skipUnless(CMD.exists(), "需要 Windows 系统文件")
class TestSarifCli(unittest.TestCase):
    def test_sarif_written(self):
        import certdiag.cli as cli

        d = Path(tempfile.mkdtemp())
        try:
            sf = d / "r.sarif"
            code = cli.main([str(CMD), "--offline", "--sarif", str(sf)])
            self.assertEqual(code, 0)
            self.assertTrue(sf.exists())
            doc = json.loads(sf.read_text(encoding="utf-8"))
            self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "certdiag")
        finally:
            cli.close_worker()

# -*- coding: utf-8 -*-
"""cli 的退出码与筛选逻辑测试

这两条是"能不能进流水线"的关键：
    - 退出码必须稳定、可预期
    - --only 必须只影响输出，不影响统计
"""
import unittest

from certdiag.cli import (EXIT_ERROR, EXIT_INVALID, EXIT_OK, EXIT_UNKNOWN,
                          count_verdicts, exit_code, filter_reports)


def rep(verdict, path="x.exe", category=None):
    return {"file": {"path": path},
            "diagnosis": {"verdict": verdict, "category": category or verdict}}


class TestExitCode(unittest.TestCase):
    def test_all_valid(self):
        self.assertEqual(exit_code([rep("valid"), rep("valid")]), EXIT_OK)

    def test_any_invalid_fails(self):
        self.assertEqual(exit_code([rep("valid"), rep("invalid")]), EXIT_INVALID)

    def test_unknown_is_ok_by_default(self):
        # 默认 fail_on=invalid：查不到吊销状态不该让流水线红
        self.assertEqual(exit_code([rep("valid"), rep("unknown")]), EXIT_OK)

    def test_unknown_strict_mode(self):
        self.assertEqual(
            exit_code([rep("unknown")], fail_on="unknown"), EXIT_UNKNOWN)

    def test_unknown_strict_still_prioritises_invalid(self):
        self.assertEqual(
            exit_code([rep("unknown"), rep("invalid")], fail_on="unknown"), EXIT_INVALID)

    def test_fail_on_none_never_fails(self):
        self.assertEqual(exit_code([rep("invalid")], fail_on="none"), EXIT_OK)

    def test_empty_is_error(self):
        self.assertEqual(exit_code([]), EXIT_ERROR)

    def test_count_verdicts(self):
        c = count_verdicts([rep("valid"), rep("invalid"), rep("unknown"), rep("valid")])
        self.assertEqual(c["valid"], 2)
        self.assertEqual(c["invalid"], 1)
        self.assertEqual(c["unknown"], 1)


class TestOnlyFilter(unittest.TestCase):
    def setUp(self):
        self.reports = [rep("valid", "a.exe"), rep("invalid", "b.exe"),
                        rep("unknown", "c.exe")]

    def test_all(self):
        self.assertEqual(len(filter_reports(self.reports, "all")), 3)

    def test_invalid_only(self):
        out = filter_reports(self.reports, "invalid")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["file"]["path"], "b.exe")

    def test_filter_does_not_mutate(self):
        filter_reports(self.reports, "invalid")
        self.assertEqual(len(self.reports), 3)

    def test_missing_verdict_treated_as_unknown(self):
        out = filter_reports([{"file": {}, "diagnosis": {}}], "unknown")
        self.assertEqual(len(out), 1)


if __name__ == "__main__":
    unittest.main()


class TestRevokeTimeout(unittest.TestCase):
    """--revoke-timeout：超时要写"未检查"，不能拖 30 秒后给个模糊错误。"""

    def test_timeout_reason_is_explicit(self):
        import time as _time
        from pathlib import Path as _P
        from unittest.mock import patch

        import certdiag.cli as cli

        real_collect = cli.collect

        def fake_collect(p, revoke="NoCheck", **kw):
            if revoke in ("Online", "Offline"):
                _time.sleep(0.35)
                return {"path": str(p), "error": "采集超时"}
            return real_collect(p, revoke=revoke, **kw)

        cmd = _P(r"C:\Windows\System32\cmd.exe")
        if not cmd.exists():
            self.skipTest("需要 Windows 系统文件")
        with patch.object(cli, "collect", fake_collect):
            rep = cli.diagnose_one(cmd, offline=False, no_probe=True, timeout=5,
                                   revoke_mode="online", revoke_timeout=0.2)
        missing = " ".join(rep["diagnosis"]["not_checked"])
        self.assertIn("吊销检查超时", missing, missing)

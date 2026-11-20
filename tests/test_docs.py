# -*- coding: utf-8 -*-
"""文档一致性检查。

这些断言防的是"文档与代码各说各话"——上一版 README 把下载链接写死在 1.5.0，
而代码已经是 2.1.1；打包脚本的使用说明也写死版本号，导致包内自带错误版本。
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
BUILD = (ROOT / "tools" / "build_portable.py").read_text(encoding="utf-8")


class TestDocsConsistency(unittest.TestCase):
    def test_no_version_pinned_download_link(self):
        """下载链接必须指向 /releases/latest，否则每次发版都会过期。"""
        pinned = re.findall(r"releases/download/v\d", README)
        self.assertEqual(pinned, [], "README 里还有写死版本的下载链接")

    def test_no_hardcoded_portable_dirname(self):
        """README 里不应出现 certdiag-portable-2.1.2 这类具体目录名。"""
        found = re.findall(r"certdiag-portable-\d+\.\d+", README)
        self.assertEqual(found, [], "README 里写死了便携包目录名")

    def test_build_script_uses_version_from_package(self):
        self.assertIn("__version__", BUILD, "打包脚本应从 certdiag.__version__ 取版本")
        self.assertNotRegex(BUILD, r"certdiag-portable-\d+\.\d+",
                            "打包脚本里写死了便携包目录名")

    def test_usage_text_is_templated(self):
        """使用说明必须用 {ver} 占位，并在写入时替换。"""
        self.assertIn("{ver}", BUILD, "使用说明应使用 {ver} 占位")
        self.assertIn('USAGE_TXT.replace("{ver}", ver)', BUILD,
                      "写入时应把 {ver} 替换成实际版本")

    def test_readme_test_count_is_current(self):
        """README 里的测试数量不能与真实数量差太远（容许漏更新一次）。"""
        m = re.search(r"Ran (\d+) tests", README)
        self.assertIsNotNone(m, "README 应写明测试数量")
        claimed = int(m.group(1))
        actual = len(list((ROOT / "tests").glob("test_*.py")))
        self.assertGreater(claimed, 100, f"测试数量看起来过期了：{claimed}")
        self.assertGreater(actual, 0)


if __name__ == "__main__":
    unittest.main()

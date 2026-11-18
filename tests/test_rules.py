# -*- coding: utf-8 -*-
"""规则表覆盖率测试

作用：防止「代码里产出了某个分类，但规则表里没写」这种漂移。
     attrib.py 里新增一个分类却忘了同步 rules.py，这里就会红。
"""
import unittest

from certdiag.report import CATEGORY_LABEL
from certdiag.rules import DYNAMIC_PREFIXES, RED_LINES, RULES, as_json, ids


class TestRulesCoverage(unittest.TestCase):
    def test_every_labelled_category_is_documented(self):
        documented = ids()
        missing = [c for c in CATEGORY_LABEL
                   if c not in documented
                   and not any(c.startswith(p) for p in DYNAMIC_PREFIXES)]
        self.assertEqual(missing, [], f"这些分类在 rules.py 里没有说明：{missing}")

    def test_no_duplicate_ids(self):
        all_ids = [r["id"] for r in RULES]
        self.assertEqual(len(all_ids), len(set(all_ids)))

    def test_verdicts_are_valid_values(self):
        for r in RULES:
            self.assertIn(r["verdict"], ("valid", "invalid", "unknown"), r["id"])
            self.assertTrue(r["title"] and r["when"] and r["action"], r["id"])

    def test_red_lines_present(self):
        # 红线是这份规则的灵魂，不允许被删空
        self.assertGreaterEqual(len(RED_LINES), 4)

    def test_json_roundtrip(self):
        import json

        data = json.loads(as_json())
        self.assertEqual(data["version"], 1)
        self.assertEqual(len(data["rules"]), len(RULES))
        self.assertIn("red_lines", data)


if __name__ == "__main__":
    unittest.main()

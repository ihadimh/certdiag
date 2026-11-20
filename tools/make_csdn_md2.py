# -*- coding: utf-8 -*-
"""生成第二篇文章的 CSDN Markdown 版。

要点（第一篇踩过的坑）：
  1. CSDN 已把标题放页头，正文里的 `#` 会变成重复的二级标题 → 删掉 H1
  2. CSDN 把 `#` 渲染成 h2、`##` 渲染成 h3 → 段落标题整体上提一级
  3. 图片要手动上传 → 留占位注释，方便定位
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "article-ci-badge.md"
OUT = ROOT / "dist" / "article-package2" / "文章2-CSDN.md"

text = SRC.read_text(encoding="utf-8")
lines = text.splitlines()

out: list[str] = []
in_code = False

for line in lines:
    if line.startswith("```"):
        in_code = not in_code
        out.append(line)
        continue
    if in_code:
        out.append(line)
        continue

    # 去掉 H1（标题已在页头）
    if line.startswith("# "):
        continue

    # 段落标题上提一级：## -> #，### -> ##
    m = re.match(r"^(#{2,4})\s+(.*)$", line)
    if m:
        out.append("#" * (len(m.group(1)) - 1) + " " + m.group(2))
        continue

    # 图片换成占位注释
    m = re.match(r"^!\[(.*?)\]\((.*?)\)$", line.strip())
    if m:
        alt, src = m.group(1), m.group(2)
        out.append(f"<!-- 在此插入图片：{alt}（文件 {src}）——删掉本行，把图片拖进编辑器 -->")
        continue

    out.append(line)

result = "\n".join(out)
OUT.write_text(result, encoding="utf-8")

print("已生成:", OUT.name)
print("图片占位:", result.count("<!-- 在此插入图片"))
print("H1 残留:", len(re.findall(r"^# ", result, re.M)))
print("标题层级:", re.findall(r"^(#{1,3}) ", result, re.M)[:10])

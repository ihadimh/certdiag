# -*- coding: utf-8 -*-
"""检查 CSDN 文章的渲染结果：标题、标签、图片、代码块、层级结构。"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from lxml import html
# 控制台编码保护：英文 Windows 的 stdout 是 cp1252，print 中文会直接抛
# UnicodeEncodeError。这里只保证"不崩"，显示效果交给 chcp。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001
        pass

p = Path(sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\ASUS\AppData\Local\Temp\csdn.html")
doc = html.fromstring(p.read_bytes())

def first(xp, root=doc):
    r = root.xpath(xp)
    return r[0] if r else None

def text(xp, root=doc):
    r = root.xpath(xp)
    return r[0].text_content().strip() if r else ""

print("标题:", text("//h1"))
print("作者:", text('//a[contains(@class,"follow-nickName")]'))
print("发布时间:", text('//span[contains(@class,"time")]'))

tags = doc.xpath('//div[contains(@class,"article-tags")]//a') or doc.xpath('//span[contains(@class,"tag")]')
print("标签:", ", ".join(t.text_content().strip() for t in tags if t.text_content().strip()) or "（未找到）")

body = first('//div[@id="content_views"]')
if body is None:
    print("!! 没找到正文容器")
    sys.exit(1)

# 结构：按子节点统计
blocks = body.xpath('./*')
print(f"\n正文顶层节点: {len(blocks)}")

pre = body.xpath('.//pre')
code = body.xpath('.//code')
imgs = body.xpath('.//img')
h2 = body.xpath('.//h2')
h3 = body.xpath('.//h3')
tables = body.xpath('.//table')
print(f"h2: {len(h2)}  h3: {len(h3)}  pre: {len(pre)}  code: {len(code)}  img: {len(imgs)}  table: {len(tables)}")

print("\n--- 目录结构 ---")
for el in body.xpath('.//h2 | .//h3'):
    lvl = el.tag
    print(f"  {lvl}: {el.text_content().strip()[:60]}")

print("\n--- 图片 ---")
for i, im in enumerate(imgs, 1):
    src = im.get("src") or im.get("data-src") or ""
    src = src[:120]
    parent = im.getparent()
    cap = ""
    nxt = parent.getnext()
    if nxt is not None:
        cap = nxt.text_content().strip()[:60]
    print(f"  {i}. {src}")
    print(f"     后一段: {cap}")

print("\n--- 代码块（前 3 行 + 语言）---")
for i, pr in enumerate(pre[:8], 1):
    cls = pr.get("class", "")
    code_el = pr.find(".//code")
    lang = ""
    if code_el is not None:
        m = re.search(r"language-(\w+)", code_el.get("class", ""))
        lang = m.group(1) if m else ""
    body_text = pr.text_content().strip().splitlines()
    head = " / ".join(x.strip() for x in body_text[:2])
    print(f"  {i}. [{lang or '无语言'}] {cls[:40]}  {head[:90]}")

print("\n--- 首段 ---")
first_p = body.xpath('.//p')
if first_p:
    print(" ", first_p[0].text_content().strip()[:120])

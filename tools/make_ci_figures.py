# -*- coding: utf-8 -*-
"""为 CI 那篇文章生成两张配图（真实日志片段，未改写内容）。"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(r"C:\Users\ASUS\Documents\deepseek-harness\default-workspace\certdiag\docs\images")
MONO = r"C:\Windows\Fonts\consola.ttf"
CJK = r"C:\Windows\Fonts\msyh.ttc"
CJK_B = r"C:\Windows\Fonts\msyhbd.ttc"

W = 1400
PAD = 32
FS = 20
LH = 32
BG = (13, 17, 23)
FG = (214, 219, 227)
DIM = (139, 148, 158)
RED = (255, 123, 114)
GREEN = (126, 231, 135)
BLUE = (121, 192, 255)
BAR = (22, 27, 34)


def font_for(text: str, size: int = FS):
    path = CJK if any(ord(c) > 127 for c in text) else MONO
    return ImageFont.truetype(path, size)


def render(lines: list[tuple[str, tuple]], title: str, dst: Path) -> None:
    head = 52
    h = head + 24 + len(lines) * LH + 28
    img = Image.new("RGB", (W, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 40], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([16 + i * 24, 14, 30 + i * 24, 28], fill=c)
    d.text((W / 2, 20), title, font=ImageFont.truetype(CJK, 15), fill=DIM, anchor="mm")

    y = head + 16
    for text, color in lines:
        if text:
            d.text((PAD, y), text, font=font_for(text), fill=color)
        y += LH
    img.save(dst)
    print(dst.name, img.size)


log1 = [
    ("# 第一次：路径长短形式不一致", DIM),
    ("FAIL: test_chinese_and_space_path_via_worker", RED),
    (r"'C:\Users\runneradmin\AppData\Local\Temp\...\中文 文件.exe'", FG),
    (r"'C:\Users\RUNNER~1\AppData\Local\Temp\...\中文 文件.exe'", RED),
    ("", FG),
    ("# 第二次：英文 runner 的编码是 cp1252", DIM),
    ("UnicodeEncodeError: 'charmap' codec can't encode", RED),
    ("characters in position 13-16: character maps to <undefined>", RED),
    ("", FG),
    ("# 第三次：脚本方式运行时 sys.path[0] 是 tools/", DIM),
    ("[check_versions] 检查本身出错：ModuleNotFoundError:", RED),
    ("No module named 'certdiag'", RED),
]

log2 = [
    ("# GitHub Actions", DIM),
    ("test (3.10)  success", GREEN),
    ("test (3.12)  success", GREEN),
    ("", FG),
    ("徽章：tests passing", GREEN),
    ("", FG),
    ("# 本地补充的三层验证", DIM),
    ("128 个单元测试", FG),
    ("tools/check_docs.py    9 组文档一致性", FG),
    ("tools/ui_selftest.py   12 项 HTTP 自检", FG),
    ("PYTHONIOENCODING=cp1252 / python -I  复现 CI 环境", FG),
]

render(log1, "GitHub Actions — 三次失败", OUT / "fig-ci-failures.png")
render(log2, "GitHub Actions — 恢复绿色", OUT / "fig-ci-success.png")

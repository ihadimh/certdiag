# -*- coding: utf-8 -*-
"""render_shots.py — 把真实命令输出渲染成配图

产物是"把终端输出画成图片"，不是屏幕截图；文字内容来自实际运行，未改写。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

SHOTS = Path(r"C:\Users\ASUS\Desktop\certdiag-shots")
MONO = r"C:\Windows\Fonts\consola.ttf"
CJK = r"C:\Windows\Fonts\msyh.ttc"

W = 1500
PAD_X = 34
TOP = 96
LINE_H = 34
FS = 21
BG = (13, 17, 23)
FG = (214, 219, 227)
DIM = (139, 148, 158)
GREEN = (126, 231, 135)
RED = (255, 123, 114)
AMBER = (227, 179, 65)
BAR = (22, 27, 34)


def load(p: Path) -> list[str]:
    txt = p.read_text(encoding="utf-8-sig")
    return [l.rstrip("\n") for l in txt.splitlines()]


EMOJI = {"\u2705": "", "\u274c": "", "\u26a0\ufe0f": "", "\u26a0": ""}


def clean(line: str) -> str:
    """PIL 没有彩色 emoji 字体，换成彩色圆点，避免渲染成方框。"""
    s = line
    for e in EMOJI:
        s = s.replace(e, "")
    s = s.strip()
    return s


def color_for(line: str):
    s = line.strip()
    if s.startswith("\u7ed3\u8bba"):
        if "\u65e0\u6548" in s:
            return RED
        if "\u6709\u6548" in s:
            return GREEN
        if "\u65e0\u6cd5\u5224\u5b9a" in s:
            return AMBER
    if s.startswith("✅"):
        return GREEN
    if s.startswith("❌"):
        return RED
    if s.startswith("⚠️") or s.startswith("⚠"):
        return AMBER
    if set(s) <= {"-"} and s:
        return (48, 54, 61)
    if s.startswith("文件："):
        return (121, 192, 255)
    return FG


def wrap(line: str, font, maxw: int) -> list[str]:
    if not line:
        return [""]
    out, cur = [], ""
    for ch in line:
        if font.getlength(cur + ch) > maxw:
            out.append(cur)
            cur = ch
        else:
            cur += ch
    out.append(cur)
    return out


def render(src: Path, dst: Path, command: str, title: str = "certdiag — Windows 签名诊断") -> Path:
    lines = load(src)
    mono = ImageFont.truetype(MONO, FS)
    cjk = ImageFont.truetype(CJK, FS)
    mono_s = ImageFont.truetype(MONO, 17)
    cjk_s = ImageFont.truetype(CJK, 17)

    maxw = W - PAD_X * 2 - 26
    rendered: list[tuple[str, object, tuple]] = []
    for ln in lines:
        raw = ln
        ln = clean(ln)
        if raw.strip()[:1] in ("\u2705", "\u274c", "\u26a0") or ln.startswith("\u7ed3\u8bba"):
            ln = "\u25cf " + ln
        f = cjk if any(ord(c) > 127 for c in ln) else mono
        for piece in wrap(ln, f, maxw):
            rendered.append((piece, cjk if any(ord(c) > 127 for c in piece) else mono,
                             color_for(raw if "piece" in dir() else piece)))

    head_h = 58
    cmd_lines = wrap(command, mono_s, W - PAD_X * 2 - 30)
    h = TOP + head_h + len(cmd_lines) * 30 + len(rendered) * LINE_H + 40

    img = Image.new("RGB", (W, h), BG)
    d = ImageDraw.Draw(img)

    # 窗口chrome
    d.rectangle([0, 0, W, 46], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([18 + i * 26, 16, 34 + i * 26, 32], fill=c)
    d.text((W / 2, 23), title, font=cjk_s, fill=DIM, anchor="mm")

    y = 70
    for ln in cmd_lines:
        d.text((PAD_X, y), ln, font=mono_s, fill=(158, 168, 180))
        y += 30

    y += 6
    for piece, f, color in rendered:
        d.text((PAD_X, y), piece, font=f, fill=color)
        y += LINE_H

    img.save(dst)
    return dst


def main() -> int:
    jobs = [
        ("txt1.txt", "fig1-catalog.png",
         "PS C:\\certdiag> python -m certdiag C:\\Windows\\System32\\cmd.exe --no-probe"),
        ("txt2.txt", "fig2-invalid.png",
         "PS C:\\certdiag> python -m certdiag X:\\tampered.exe --no-probe"),
        ("txt3.txt", "fig3-batch.png",
         "PS C:\\certdiag> python -m certdiag C:\\s --no-probe -q"),
    ]
    for src, dst, cmd in jobs:
        p = render(SHOTS / src, SHOTS / dst, cmd)
        print(f"{p.name}  {Image.open(p).size}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

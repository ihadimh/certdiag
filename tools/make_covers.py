# -*- coding: utf-8 -*-
"""make_covers.py — 生成 CSDN 封面候选（1200x800）"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(r"C:\Users\ASUS\Desktop\certdiag-shots")
W, H = 1200, 800
BG = (13, 17, 23)
FG = (230, 237, 243)
DIM = (139, 148, 158)
ACCENT = (88, 166, 255)
GREEN = (126, 231, 135)
RED = (255, 123, 114)
AMBER = (227, 179, 65)

BOLD = r"C:\Windows\Fonts\msyhbd.ttc"
REG = r"C:\Windows\Fonts\msyh.ttc"
MONO = r"C:\Windows\Fonts\consola.ttf"



def pick(text: str, mono_path: str, cjk_path: str, size: int):
    """Consolas 没有 CJK 字形，含中文的行必须换字体，否则渲染成方框。"""
    path = cjk_path if any(ord(c) > 127 for c in text) else mono_path
    return ImageFont.truetype(path, size)

def grid(d: ImageDraw.ImageDraw) -> None:
    for x in range(0, W, 40):
        d.line([(x, 0), (x, H)], fill=(19, 23, 30), width=1)
    for y in range(0, H, 40):
        d.line([(0, y), (W, y)], fill=(19, 23, 30), width=1)


def cover_a() -> Path:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    grid(d)

    f_brand = ImageFont.truetype(BOLD, 26)
    f_big = ImageFont.truetype(BOLD, 74)
    f_sub = ImageFont.truetype(REG, 32)
    f_mono = ImageFont.truetype(MONO, 22)

    d.text((80, 78), "certdiag", font=f_brand, fill=ACCENT)
    d.text((80, 175), "Windows 说「签名无效」", font=f_big, fill=FG)
    d.text((80, 275), "可能根本不是签名的问题", font=f_big, fill=FG)
    d.text((80, 392), "证书过期 · 根证书缺失 · 文件被改 · 查不到吊销", font=f_sub, fill=DIM)

    # 底部：迷你终端
    box = [80, 500, W - 80, 700]
    d.rounded_rectangle(box, radius=12, fill=(16, 21, 27), outline=(48, 54, 61), width=1)
    lines = [
        ("C:\\> certdiag app.exe", DIM),
        ("", DIM),
        ("结论：有效 — 由目录签名（catalog）覆盖", GREEN),
        ("结论：有效 — 证书过期，但时间戳有效", GREEN),
        ("结论：无效 — 内容与签名不匹配", RED),
        ("结论：无法判定 — 本机查不到吊销状态", AMBER),
    ]
    y = 528
    for text, color in lines:
        d.text((112, y), text, font=pick(text, MONO, REG, 22), fill=color)
        y += 27
    img.save(OUT / "cover-a.png")
    return OUT / "cover-a.png"


def cover_b() -> Path:
    img = Image.new("RGB", (W, H), (11, 15, 20))
    d = ImageDraw.Draw(img)
    grid(d)

    f_brand = ImageFont.truetype(BOLD, 24)
    f_big = ImageFont.truetype(BOLD, 62)
    f_small = ImageFont.truetype(REG, 26)
    f_mono = ImageFont.truetype(MONO, 20)

    # 右侧卡片
    d.rounded_rectangle([650, 120, 1120, 680], radius=14, fill=(16, 21, 27), outline=(48, 54, 61))
    rows = [
        ("catalog_only_trust", GREEN),
        ("expired_with_timestamp", GREEN),
        ("untrusted_root", RED),
        ("TRUST_E_BAD_DIGEST", RED),
        ("valid_revocation_unchecked", AMBER),
        ("corrupt_pe", AMBER),
    ]
    y = 160
    for name, color in rows:
        d.ellipse([680, y + 8, 694, y + 22], fill=color)
        d.text((710, y), name, font=f_mono, fill=(200, 208, 218))
        y += 62
    d.text((680, 570), "分类 + 证据 + 置信度", font=f_small, fill=DIM)

    d.text((80, 300), "把「签名无效」", font=f_big, fill=FG)
    d.text((80, 380), "拆成四类原因", font=f_big, fill=FG)
    d.text((80, 480), "certdiag · 只读诊断", font=f_small, fill=ACCENT)
    d.text((80, 520), "Python + PowerShell · MIT", font=f_small, fill=DIM)
    img.save(OUT / "cover-b.png")
    return OUT / "cover-b.png"


def cover_c() -> Path:
    """浅色版：适合在信息流里显得干净。"""
    img = Image.new("RGB", (W, H), (246, 248, 250))
    d = ImageDraw.Draw(img)
    for x in range(0, W, 40):
        d.line([(x, 0), (x, H)], fill=(238, 241, 244), width=1)
    for y in range(0, H, 40):
        d.line([(0, y), (W, y)], fill=(238, 241, 244), width=1)

    f_big = ImageFont.truetype(BOLD, 66)
    f_sub = ImageFont.truetype(REG, 30)
    f_mono = ImageFont.truetype(MONO, 21)

    d.text((80, 170), "签名无效？", font=f_big, fill=(31, 35, 40))
    d.text((80, 258), "先分清这四种情况", font=f_big, fill=(9, 105, 218))
    d.text((80, 372), "证书过期 / 根不受信 / 文件被改 / 查不到吊销", font=f_sub, fill=(87, 96, 106))

    box = [80, 470, W - 80, 690]
    d.rounded_rectangle(box, radius=12, fill=(13, 17, 23))
    lines = [
        ("结论：有效 — 目录签名覆盖", GREEN),
        ("结论：有效 — 过期但时间戳有效", GREEN),
        ("结论：无效 — 内容与签名不匹配", RED),
        ("结论：无法判定 — 吊销状态未检查", AMBER),
    ]
    y = 500
    for text, color in lines:
        d.text((110, y), text, font=pick(text, MONO, REG, 21), fill=color)
        y += 42
    d.text((80, 720), "certdiag · github.com/ihadimh/certdiag", font=f_mono, fill=(87, 96, 106))
    img.save(OUT / "cover-c.png")
    return OUT / "cover-c.png"


if __name__ == "__main__":
    for fn in (cover_a, cover_b, cover_c):
        print(fn().name)
    sys.exit(0)

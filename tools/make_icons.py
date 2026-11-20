"""make_icons.py — 生成多个图标方案供挑选

六个方向：
    1 seal    火漆封缄（隐喻"已签署"）
    2 doc     文件 + 对勾徽章（最直白）
    3 chain   两环相扣（证书链）
    4 lens    放大镜看文件（检查动作）
    5 lock    文件 + 锁（受保护）
    6 shield  盾牌（当前方案，用于对比）

全部按 512 绘制再缩放，避免小尺寸发糊；背景透明，桌面/深色模式下都能用。
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
import sys
# 控制台编码保护：英文 Windows 的 stdout 是 cp1252，print 中文会直接抛
# UnicodeEncodeError。这里只保证"不崩"，显示效果交给 chcp。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001
        pass

OUT = Path(__file__).resolve().parent.parent / "docs" / "icons"
S = 512          # 绘制基准尺寸
INK = (15, 23, 42, 255)
CYAN = (56, 189, 248, 255)
GREEN = (34, 197, 94, 255)
WHITE = (248, 250, 252, 255)
GRAY = (148, 163, 184, 255)
PAPER = (241, 245, 249, 255)
RED = (185, 28, 28, 255)
DARKRED = (127, 29, 29, 255)


def canvas() -> Image.Image:
    return Image.new("RGBA", (S, S), (0, 0, 0, 0))


def check(d, x0, y0, x1, y1, x2, y2, color, w):
    d.line([(x0, y0), (x1, y1)], fill=color, width=w, joint="curve")
    d.line([(x1, y1), (x2, y2)], fill=color, width=w, joint="curve")
    for px, py in ((x0, y0), (x1, y1), (x2, y2)):
        r = w / 2
        d.ellipse([px - r, py - r, px + r, py + r], fill=color)


# ---------------- 1. 火漆封缄 ----------------
SEAL_PALETTES = {
    # 亮红（当前）
    "seal": dict(wax=(185, 28, 28, 255), inner=(127, 29, 29, 255),
                 ribbon=(127, 29, 29, 255), mark=(252, 211, 77, 255)),
    # 暗红磨砂：降饱和 + 压暗，接近真实封蜡
    "seal_matte": dict(wax=(122, 45, 45, 255), inner=(84, 30, 30, 255),
                       ribbon=(84, 30, 30, 255), mark=(216, 180, 106, 255)),
    # 青绿封蜡：与界面配色统一
    "seal_teal": dict(wax=(15, 118, 110, 255), inner=(19, 78, 74, 255),
                      ribbon=(17, 94, 89, 255), mark=(167, 243, 208, 255)),
}


def icon_seal(palette: str = "seal") -> Image.Image:
    pal = SEAL_PALETTES[palette]
    RED = pal["wax"]
    DARKRED = pal["inner"]
    img = canvas()
    d = ImageDraw.Draw(img)
    cx, cy = S * 0.5, S * 0.44
    r = S * 0.30

    # 缎带
    d.polygon([(cx - r * 0.55, cy + r * 0.75), (cx - r * 1.25, S * 0.95),
               (cx - r * 0.55, S * 0.92), (cx - r * 0.15, S * 0.98)], fill=DARKRED)
    d.polygon([(cx + r * 0.55, cy + r * 0.75), (cx + r * 1.25, S * 0.95),
               (cx + r * 0.55, S * 0.92), (cx + r * 0.15, S * 0.98)], fill=DARKRED)

    # 波浪边
    for i in range(30):
        a = 2 * math.pi * i / 30
        px, py = cx + r * 0.95 * math.cos(a), cy + r * 0.95 * math.sin(a)
        rr = r * 0.14
        d.ellipse([px - rr, py - rr, px + rr, py + rr], fill=RED)

    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=RED)
    d.ellipse([cx - r * 0.74, cy - r * 0.74, cx + r * 0.74, cy + r * 0.74],
              fill=DARKRED)
    check(d, cx - r * 0.42, cy + r * 0.02, cx - r * 0.10, cy + r * 0.32,
          cx + r * 0.44, cy - r * 0.34, pal["mark"], int(S * 0.055))
    return img


# ---------------- 2. 文件 + 对勾徽章 ----------------
def icon_doc() -> Image.Image:
    img = canvas()
    d = ImageDraw.Draw(img)
    x0, y0, x1, y1 = S * 0.20, S * 0.12, S * 0.72, S * 0.80
    fold = S * 0.14

    d.rounded_rectangle([x0, y0, x1, y1], radius=S * 0.05, fill=PAPER,
                        outline=(100, 116, 139, 255), width=int(S * 0.018))
    d.polygon([(x1 - fold, y0), (x1, y0 + fold), (x1 - fold, y0 + fold)], fill=GRAY)
    for i in range(3):
        yy = y0 + S * 0.20 + i * S * 0.11
        d.rounded_rectangle([x0 + S * 0.07, yy, x1 - S * 0.10 - i * S * 0.05, yy + S * 0.045],
                            radius=S * 0.02, fill=GRAY)

    bx, by, br = S * 0.70, S * 0.71, S * 0.17
    d.ellipse([bx - br, by - br, bx + br, by + br], fill=WHITE)
    d.ellipse([bx - br * 0.90, by - br * 0.90, bx + br * 0.90, by + br * 0.90], fill=GREEN)
    check(d, bx - br * 0.45, by + br * 0.02, bx - br * 0.10, by + br * 0.36,
          bx + br * 0.48, by - br * 0.34, WHITE, int(S * 0.045))
    return img


# ---------------- 3. 两环相扣 ----------------
def icon_chain() -> Image.Image:
    """两个圆环相交，其中一个在相交处断开，形成"套在一起"的观感。"""
    img = canvas()
    d = ImageDraw.Draw(img)
    w = int(S * 0.062)
    r = S * 0.20
    c1 = (S * 0.40, S * 0.40)
    c2 = (S * 0.60, S * 0.60)

    def box(c, rr):
        return [c[0] - rr, c[1] - rr, c[0] + rr, c[1] + rr]

    # 后环整圈
    d.ellipse(box(c1, r), outline=CYAN, width=w)
    # 前环：缺口朝向另一个环，看起来像从后面穿过
    d.arc(box(c2, r), start=280, end=169, fill=CYAN, width=w)
    # 断口两端补圆头，避免直角
    for ang in (280, 169):
        a = math.radians(ang)
        px, py = c2[0] + r * math.cos(a), c2[1] + r * math.sin(a)
        d.ellipse([px - w / 2, py - w / 2, px + w / 2, py + w / 2], fill=CYAN)
    return img


# ---------------- 4. 放大镜看文件 ----------------
def icon_lens() -> Image.Image:
    img = canvas()
    d = ImageDraw.Draw(img)
    x0, y0, x1, y1 = S * 0.14, S * 0.10, S * 0.64, S * 0.76
    d.rounded_rectangle([x0, y0, x1, y1], radius=S * 0.05, fill=PAPER,
                        outline=(100, 116, 139, 255), width=int(S * 0.018))
    for i in range(3):
        yy = y0 + S * 0.18 + i * S * 0.12
        d.rounded_rectangle([x0 + S * 0.07, yy, x1 - S * 0.08, yy + S * 0.045],
                            radius=S * 0.02, fill=GRAY)

    cx, cy, r = S * 0.62, S * 0.56, S * 0.22
    d.line([(cx + r * 0.68, cy + r * 0.68), (S * 0.90, S * 0.86)],
           fill=INK, width=int(S * 0.085))
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 255, 255, 235),
              outline=INK, width=int(S * 0.055))
    check(d, cx - r * 0.45, cy + r * 0.02, cx - r * 0.08, cy + r * 0.36,
          cx + r * 0.48, cy - r * 0.36, GREEN, int(S * 0.05))
    return img


# ---------------- 5. 文件 + 锁 ----------------
def icon_lock() -> Image.Image:
    img = canvas()
    d = ImageDraw.Draw(img)
    x0, y0, x1, y1 = S * 0.16, S * 0.08, S * 0.66, S * 0.56
    d.rounded_rectangle([x0, y0, x1, y1], radius=S * 0.05, fill=PAPER,
                        outline=(100, 116, 139, 255), width=int(S * 0.018))
    for i in range(2):
        yy = y0 + S * 0.13 + i * S * 0.11
        d.rounded_rectangle([x0 + S * 0.06, yy, x1 - S * 0.10, yy + S * 0.042],
                            radius=S * 0.02, fill=GRAY)

    cx, cy = S * 0.58, S * 0.66
    bw, bh = S * 0.30, S * 0.24
    sw = bw * 0.62
    # 锁梁（上半圆）
    d.arc([cx - sw / 2, cy - sw / 2, cx + sw / 2, cy + sw / 2],
          start=180, end=360, fill=CYAN, width=int(S * 0.055))
    d.line([(cx - sw / 2, cy), (cx - sw / 2, cy + S * 0.02)],
           fill=CYAN, width=int(S * 0.055))
    d.line([(cx + sw / 2, cy), (cx + sw / 2, cy + S * 0.02)],
           fill=CYAN, width=int(S * 0.055))
    # 锁体
    d.rounded_rectangle([cx - bw / 2, cy, cx + bw / 2, cy + bh],
                        radius=S * 0.045, fill=CYAN)
    # 锁孔
    kx, ky = cx, cy + bh * 0.34
    d.ellipse([kx - S * 0.032, ky - S * 0.032, kx + S * 0.032, ky + S * 0.032], fill=INK)
    d.rounded_rectangle([kx - S * 0.013, ky, kx + S * 0.013, ky + bh * 0.34],
                        radius=S * 0.011, fill=INK)
    return img


# ---------------- 6. 盾牌（现有） ----------------
def icon_shield() -> Image.Image:
    img = canvas()
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=int(S * 0.22), fill=INK)
    pad = S * 0.24
    pts = [(pad, pad + S * 0.05), (S / 2, pad), (S - pad, pad + S * 0.05),
           (S - pad, S * 0.52), (S / 2, S - pad * 0.6), (pad, S * 0.52)]
    d.polygon(pts, fill=(30, 41, 59, 255), outline=CYAN, width=int(S * 0.045))
    check(d, S * 0.365, S * 0.50, S * 0.455, S * 0.615, S * 0.645, S * 0.385,
          GREEN, int(S * 0.085))
    return img


ICONS = [
    ("seal", "火漆封缄", icon_seal),
    ("seal_matte", "暗红磨砂", lambda: icon_seal("seal_matte")),
    ("seal_teal", "青绿封蜡", lambda: icon_seal("seal_teal")),
    ("doc", "文件+徽章", icon_doc),
    ("chain", "两环相扣", icon_chain),
    ("lens", "放大镜", icon_lens),
    ("lock", "文件+锁", icon_lock),
    ("shield", "盾牌（现用）", icon_shield),
]


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        font = ImageFont.truetype(r"C:\Windows\Fonts\msyh.ttc", 26)
    except OSError:
        font = ImageFont.load_default()

    rendered = {}
    for key, label, fn in ICONS:
        img = fn()
        img.save(OUT / f"{key}-256.png")
        img.resize((32, 32), Image.LANCZOS).save(OUT / f"{key}-32.png")
        rendered[key] = (label, img)

    # 对比图：白底 + 深底，各尺寸
    cols = len(ICONS)
    cell = 190
    sheet = Image.new("RGB", (cols * cell + 40, 460), (255, 255, 255))
    d = ImageDraw.Draw(sheet)
    d.rectangle([0, 240, sheet.width, 460], fill=(15, 23, 42))

    for i, (key, label, fn) in enumerate(ICONS):
        x = 20 + i * cell
        big = rendered[key][1].resize((128, 128), Image.LANCZOS)
        sheet.paste(big, (x + 30, 40), big)
        d.text((x + 20, 180), label, fill=(15, 23, 42), font=font)
        d.text((x + 20, 212), key, fill=(120, 130, 145), font=font)

        sm = rendered[key][1].resize((48, 48), Image.LANCZOS)
        sheet.paste(sm, (x + 36, 270), sm)
        tiny = rendered[key][1].resize((24, 24), Image.LANCZOS)
        sheet.paste(tiny, (x + 110, 282), tiny)
        d.text((x + 20, 340), label, fill=(226, 232, 240), font=font)

    sheet.save(OUT.parent / "icon-options.png")
    print(f"[+] {OUT.parent / 'icon-options.png'}")
    print("[+] 单张：" + ", ".join(k for k, _, _ in ICONS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

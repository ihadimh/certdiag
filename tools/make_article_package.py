# -*- coding: utf-8 -*-
"""make_article_package.py — 把文章打成"图片内嵌"的单文件

为什么需要：
    CSDN 的 Markdown 编辑器不接受本地相对路径的图片，得一张张手动传。
    把图做成 base64 内嵌后：
      - 单文件 HTML：浏览器打开 → 全选复制 → 粘进 CSDN 富文本编辑器，图会一起过去
      - DOCX：Word 里图片是嵌入的，粘过去同样带图
      - 自包含 Markdown：Typora / VS Code 预览能直接显示

用法：
    python tools/make_article_package.py docs/article-introduction.md
"""
from __future__ import annotations

import base64
import html as H
import re
import sys
from pathlib import Path

from docx import Document
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parent.parent
MONO = "Consolas"


# ---------------- 迷你 Markdown 解析 ----------------

def parse(md: str) -> list[tuple[str, object]]:
    """返回 (类型, 内容) 列表：h1/h2/h3/p/code/list/table/img/caption/hr。"""
    out: list[tuple[str, object]] = []
    lines = md.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i]
        s = ln.strip()

        if s.startswith("```"):
            lang = s[3:].strip()
            i += 1
            buf: list[str] = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            out.append(("code", (lang, "\n".join(buf))))
            continue

        m = re.match(r"^(#{1,3})\s+(.*)$", s)
        if m:
            out.append((f"h{len(m.group(1))}", m.group(2).strip()))
            i += 1
            continue

        if s == "---":
            out.append(("hr", None))
            i += 1
            continue

        m = re.match(r"^!\[(.*?)\]\((.*?)\)$", s)
        if m:
            out.append(("img", (m.group(1), m.group(2))))
            i += 1
            continue

        if s.startswith("*▲"):
            out.append(("caption", s.strip("*")))
            i += 1
            continue

        if s.startswith("|") and i + 1 < len(lines) and set(lines[i + 1].strip()) <= set("|-: "):
            header = [c.strip() for c in s.strip("|").split("|")]
            i += 2
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            out.append(("table", (header, rows)))
            continue

        if s.startswith("- "):
            items = []
            while i < len(lines) and lines[i].strip().startswith("- "):
                items.append(lines[i].strip()[2:])
                i += 1
            out.append(("list", items))
            continue

        if not s:
            i += 1
            continue

        out.append(("p", s))
        i += 1
    return out


def inline(text: str) -> str:
    """行内格式 → HTML。"""
    t = H.escape(text)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', t)
    return t


def data_uri(p: Path) -> str:
    b64 = base64.b64encode(p.read_bytes()).decode()
    return f"data:image/png;base64,{b64}"


# ---------------- HTML ----------------

CSS = """
body{max-width:860px;margin:40px auto;padding:0 20px;font:16px/1.75 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;color:#1f2328}
h1{font-size:30px;border-bottom:1px solid #d0d7de;padding-bottom:12px;margin-top:36px}
h2{font-size:23px;border-bottom:1px solid #eaeef2;padding-bottom:8px;margin-top:34px}
h3{font-size:18px;margin-top:26px}
p{margin:14px 0}
code{background:#f2f4f7;padding:2px 6px;border-radius:4px;font-family:Consolas,monospace;font-size:14px}
pre{background:#0d1117;color:#e6edf3;padding:16px 18px;border-radius:8px;overflow:auto}
pre code{background:none;color:inherit;padding:0;font-size:14px}
img{max-width:100%;display:block;margin:18px auto;border:1px solid #d0d7de;border-radius:8px}
.cap{color:#57606a;font-size:14px;text-align:center;margin-top:-8px}
table{border-collapse:collapse;margin:16px 0;width:100%}
th,td{border:1px solid #d0d7de;padding:8px 12px;text-align:left;font-size:15px}
th{background:#f6f8fa}
blockquote{border-left:4px solid #d0d7de;margin:16px 0;padding:2px 16px;color:#57606a}
a{color:#0969da}
hr{border:none;border-top:1px solid #d0d7de;margin:32px 0}
"""


def to_html(blocks, img_dir: Path) -> str:
    parts = [f"<!doctype html><html><head><meta charset='utf-8'><title>certdiag</title><style>{CSS}</style></head><body>"]
    for kind, val in blocks:
        if kind == "h1":
            parts.append(f"<h1>{inline(val)}</h1>")
        elif kind == "h2":
            parts.append(f"<h2>{inline(val)}</h2>")
        elif kind == "h3":
            parts.append(f"<h3>{inline(val)}</h3>")
        elif kind == "p":
            parts.append(f"<p>{inline(val)}</p>")
        elif kind == "caption":
            parts.append(f"<p class='cap'>{inline(val)}</p>")
        elif kind == "hr":
            parts.append("<hr>")
        elif kind == "code":
            lang, body = val
            parts.append(f"<pre><code>{H.escape(body)}</code></pre>")
        elif kind == "list":
            items = "".join(f"<li>{inline(x)}</li>" for x in val)
            parts.append(f"<ul>{items}</ul>")
        elif kind == "img":
            alt, src = val
            p = (img_dir / src).resolve()
            parts.append(f"<img alt='{H.escape(alt)}' src='{data_uri(p)}'>")
        elif kind == "table":
            header, rows = val
            th = "".join(f"<th>{inline(c)}</th>" for c in header)
            trs = "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in rows)
            parts.append(f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>")
    parts.append("</body></html>")
    return "\n".join(parts)


# ---------------- DOCX ----------------

def to_docx(blocks, img_dir: Path, out: Path) -> None:
    doc = Document()
    doc.styles["Normal"].font.name = "Microsoft YaHei"
    doc.styles["Normal"].font.size = Pt(10.5)

    for kind, val in blocks:
        if kind == "h1":
            doc.add_heading(val, level=0)
        elif kind == "h2":
            doc.add_heading(val, level=1)
        elif kind == "h3":
            doc.add_heading(val, level=2)
        elif kind == "p":
            add_rich(doc.add_paragraph(), val)
        elif kind == "caption":
            p = doc.add_paragraph()
            r = p.add_run(val)
            r.italic = True
            r.font.size = Pt(9)
            r.font.color.rgb = RGBColor(0x57, 0x60, 0x6A)
        elif kind == "code":
            lang, body = val
            p = doc.add_paragraph()
            r = p.add_run(body)
            r.font.name = MONO
            r.font.size = Pt(9)
            p.paragraph_format.left_indent = Inches(0.2)
            p.paragraph_format.space_after = Pt(8)
        elif kind == "list":
            for item in val:
                add_rich(doc.add_paragraph(style="List Bullet"), item)
        elif kind == "img":
            alt, src = val
            doc.add_picture(str((img_dir / src).resolve()), width=Inches(6.2))
        elif kind == "table":
            header, rows = val
            t = doc.add_table(rows=1, cols=len(header))
            t.style = "Table Grid"
            for i, c in enumerate(header):
                cell = t.rows[0].cells[i]
                cell.text = ""
                add_rich(cell.paragraphs[0], c)
                for run in cell.paragraphs[0].runs:
                    run.bold = True
            for r in rows:
                cells = t.add_row().cells
                for i, c in enumerate(r[: len(header)]):
                    add_rich(cells[i].paragraphs[0], c)
    doc.save(out)


def add_rich(par, text: str) -> None:
    """把 **粗体** 与 `代码` 写进段落。"""
    tokens = re.split(r"(\*\*[^*]+\*\*|`[^`]+`)", text)
    for tok in tokens:
        if not tok:
            continue
        if tok.startswith("**") and tok.endswith("**"):
            r = par.add_run(tok[2:-2])
            r.bold = True
        elif tok.startswith("`") and tok.endswith("`"):
            r = par.add_run(tok[1:-1])
            r.font.name = MONO
        else:
            par.add_run(tok)


def main() -> int:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "article-introduction.md"
    md = src.read_text(encoding="utf-8")
    img_dir = src.parent

    blocks = parse(md)
    n_img = sum(1 for k, _ in blocks if k == "img")

    out_dir = ROOT / "dist" / "article-package"
    out_dir.mkdir(parents=True, exist_ok=True)

    html_path = out_dir / "文章-自包含.html"
    html_path.write_text(to_html(blocks, img_dir), encoding="utf-8")

    # 自包含 Markdown：图片换成 data URI
    md2 = re.sub(
        r"!\[(.*?)\]\((images/[^)]+)\)",
        lambda m: f"![{m.group(1)}]({data_uri((img_dir / m.group(2)).resolve())})",
        md)
    (out_dir / "文章-自包含.md").write_text(md2, encoding="utf-8")

    docx_path = out_dir / "文章.docx"
    to_docx(blocks, img_dir, docx_path)

    for p in (html_path, out_dir / "文章-自包含.md", docx_path):
        print(f"{p.name:24s} {p.stat().st_size / 1024 / 1024:6.2f} MB")
    print(f"图片 {n_img} 张，已内嵌")
    return 0


if __name__ == "__main__":
    sys.exit(main())

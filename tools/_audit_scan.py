# -*- coding: utf-8 -*-
"""静态审计：扫一遍高风险写法，输出清单供人工判断。"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = sorted((ROOT / "certdiag").glob("*.py")) + sorted((ROOT / "tools").glob("*.py")) + [ROOT / "verify.py"]

patterns = {
    "吞异常(except: pass)": re.compile(r"except[^\n:]*:\s*(?:#.*)?\n\s*(pass|continue)\b"),
    "裸 except": re.compile(r"except\s*:"),
    "shell=True": re.compile(r"shell\s*=\s*True"),
    "os.system": re.compile(r"os\.system\("),
    "eval/exec": re.compile(r"\b(eval|exec)\("),
    "open 无 encoding": re.compile(r"open\((?![^)]*encoding)"),
    "assert 做校验": re.compile(r"^\s*assert\s+", re.M),
    "TODO/FIXME": re.compile(r"\b(TODO|FIXME|XXX)\b"),
    "硬编码临时路径": re.compile(r"[A-Z]:\\\\?(Windows|Users)"),
    "time.sleep": re.compile(r"time\.sleep\("),
}

print(f"扫描 {len(FILES)} 个文件\n")
for name, pat in patterns.items():
    hits = []
    for f in FILES:
        if f.name.startswith("_"):
            continue
        txt = f.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(pat, txt):
            line = txt[: m.start()].count("\n") + 1
            hits.append(f"{f.relative_to(ROOT)}:{line}")
    if hits:
        print(f"[{name}] {len(hits)} 处")
        for h in hits[:8]:
            print("   ", h)
        if len(hits) > 8:
            print(f"    … 还有 {len(hits) - 8} 处")
        print()

# 可变默认参数
print("[可变默认参数]")
for f in FILES:
    if f.name.startswith("_"):
        continue
    tree = ast.parse(f.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.args.defaults + node.args.kw_defaults:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    print(f"   {f.relative_to(ROOT)}:{node.lineno} {node.name}")

# -*- coding: utf-8 -*-
"""coverage_probe.py — 不依赖第三方库的行覆盖统计

用途：找出"测试从没走到的代码"。这些地方是 bug 的高发区
（`--md` 导出崩溃、junction 死循环都属于这一类）。

用法：
    python tools/coverage_probe.py           # 打印总覆盖率与未覆盖函数
    python tools/coverage_probe.py --min 75  # 低于阈值时退出码 1
"""
import dis
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PKG = ROOT / "certdiag"
FILES = {str(p.resolve()): p.name for p in PKG.glob("*.py")}
hits: dict[str, set[int]] = {f: set() for f in FILES}
calls: dict[str, set[str]] = {f: set() for f in FILES}


def tracer(frame, event, arg):
    fn = frame.f_code.co_filename
    if fn not in FILES:
        return None
    if event == "line":
        hits[fn].add(frame.f_lineno)
    elif event == "call":
        calls[fn].add(frame.f_code.co_name)
    return tracer


def run_tests():
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"))
    import io

    runner = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0)
    return runner.run(suite)


sys.settrace(tracer)
res = run_tests()
sys.settrace(None)
print(f"测试：run={res.testsRun} failures={len(res.failures)} errors={len(res.errors)}\n")

total_lines = total_hit = 0
rows = []
for fn, name in sorted(FILES.items()):
    code = compile(Path(fn).read_text(encoding="utf-8"), fn, "exec")
    executable = {ln for _, ln in dis.findlinestarts(code)}
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            executable |= {ln for _, ln in dis.findlinestarts(const)}
    executed = hits[fn] & executable
    total_lines += len(executable)
    total_hit += len(executed)
    missing = sorted(executable - hits[fn])
    if missing:
        rows.append((name, len(executable), len(executed), missing))

print(f"总行覆盖：{total_hit}/{total_lines} = {total_hit / total_lines * 100:.1f}%\n")
print("未覆盖最多的文件：")
for name, tot, cov, missing in sorted(rows, key=lambda r: -(r[1] - r[2]))[:6]:
    print(f"  {name:18s} {cov}/{tot}  未覆盖行：{missing[:14]}{' …' if len(missing) > 14 else ''}")

pct = total_hit / total_lines * 100 if total_lines else 0
print("\n测试期间从未被调用的函数（可能整段没测）：")
for fn, name in sorted(FILES.items()):
    code = compile(Path(fn).read_text(encoding="utf-8"), fn, "exec")
    funcs = [c.co_name for c in code.co_consts if isinstance(c, types.CodeType)]
    never = [f for f in funcs if f not in calls[fn] and not f.startswith("<")]
    if never:
        print(f"  {name:18s} {never}")

import argparse

ap = argparse.ArgumentParser()
ap.add_argument("--min", type=float, default=0.0, help="低于该覆盖率时退出码 1")
args = ap.parse_args()
if args.min and pct < args.min:
    print(f"\n覆盖率 {pct:.1f}% 低于阈值 {args.min}%")
    sys.exit(1)

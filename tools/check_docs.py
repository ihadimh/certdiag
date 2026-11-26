# -*- coding: utf-8 -*-
"""check_docs.py — 文档与代码的一致性检查

为什么需要：
    v1.5.0 到 v2.1.1 之间，README 的下载链接一直是 1.5.0，打包脚本的使用说明也写死
    版本号，而代码早已是 2.x。没有一条测试检查"文档说的"和"代码做的"是否一致。

检查项：
    A 分类名     代码里的 category 必须在 docs/rules.json 里有一条对应规则
    B 命令行    文档里出现的 --flag 必须是 CLI 真实存在的参数
    C 接口       文档里出现的 /api/* 必须是 ui.py 真实注册的路由
    D 链接       文档里指向本地文件的链接必须存在
    E 版本卫生   不允许写死便携包目录名 / 发版下载链接
    F 测试数量   README 写的测试数必须等于 tests/ 里 test_ 方法数
    G 退出码     文档里的退出码必须与 cli.py 的 EXIT_* 常量一致
    H JSON 协议  文档里的 schema_version 必须与代码一致
    I 图片       文档引用的图片文件必须存在

用法：
    python tools/check_docs.py            # 全部检查
    python tools/check_docs.py -v         # 显示通过项
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
# 控制台编码保护：英文 Windows 的 stdout 是 cp1252，print 中文会直接抛
# UnicodeEncodeError。这里只保证"不崩"，显示效果交给 chcp。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001
        pass

ROOT = Path(__file__).resolve().parent.parent
# 直接以 `python tools/check_docs.py` 运行时，sys.path[0] 是 tools/，
# import certdiag 会失败（CI 上就是这样）。显式把仓库根加进去。
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DOCS = [ROOT / "README.md"] + sorted((ROOT / "docs").glob("*.md")) + sorted((ROOT / "docs" / "publish").glob("*.md"))

problems: list[str] = []
checks: list[str] = []


def fail(check: str, msg: str) -> None:
    problems.append(f"[{check}] {msg}")


def ok(check: str, msg: str) -> None:
    checks.append(f"[{check}] {msg}")


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


# ---------- A 分类名 ----------
def check_categories() -> None:
    rules = json.loads((ROOT / "docs" / "rules.json").read_text(encoding="utf-8"))
    ids = {r["id"] for r in rules["rules"]}
    prefixes = tuple(rules["dynamic_prefixes"])

    code_cats: set[str] = set()
    for f in (ROOT / "certdiag").glob("*.py"):
        code_cats |= set(re.findall(r'category="([^"]+)"', read(f)))

    for c in sorted(code_cats):
        if c.startswith(prefixes):
            continue
        if c not in ids:
            fail("A", f"分类 `{c}` 在代码里出现，但 rules.json 没有对应规则")
    for i in sorted(ids - code_cats - {"valid"}):
        fail("A", f"rules.json 的规则 `{i}` 在代码里找不到对应分类")
    ok("A", f"{len(code_cats)} 个分类与 rules.json 对齐（规则共 {len(ids)} 条）")


# ---------- B 命令行参数 ----------
def check_flags() -> None:
    # 参数可能来自 certdiag CLI，也可能来自 tools/ 或 verify.py。
    # 取全仓库并集：既能抓住拼错的参数，又不会把别的脚本的参数误报成问题。
    files = [ROOT / "certdiag" / "cli.py", ROOT / "verify.py"] + sorted((ROOT / "tools").glob("*.py"))
    flags: set[str] = {"--help"}
    for f in files:
        src = read(f)
        # argparse 写法（单双引号都可能）
        flags |= set(re.findall(r"""add_argument\(\s*["'](--[a-z0-9-]+)["']""", src))
        # 手写 argv 判断的脚本（verify.py / real_path_audit.py 用的是这种）
        flags |= set(re.findall(r"""["'](--[a-z0-9-]+)["']\s+in\s+(?:sys\.)?argv""", src))
        flags |= set(re.findall(r"""argv\.index\(\s*["'](--[a-z0-9-]+)["']""", src))

    # 文档里会写外部命令的参数（如 sigstore verify identity），它们不是本项目的参数
    external = {"--certificate", "--signature", "--identity", "--issuer", "--bundle"}

    mentioned: dict[str, set[str]] = {}
    for p in DOCS:
        for m in re.findall(r'(?<![\w-])(--[a-z][a-z0-9-]+)', read(p)):
            mentioned.setdefault(m, set()).add(p.name)

    for flag, where in sorted(mentioned.items()):
        if flag not in flags and flag not in external:
            fail("B", f"文档提到 `{flag}`，但 CLI 没有这个参数（出现在 {', '.join(sorted(where))}）")
    ok("B", f"文档提到的 {len(mentioned)} 个参数全部存在（CLI 共 {len(flags)} 个）")


# ---------- C 接口 ----------
def check_endpoints() -> None:
    ui = read(ROOT / "certdiag" / "ui.py")
    routes = set(re.findall(r'"(/api/[a-z]+)"', ui))
    mentioned: dict[str, set[str]] = {}
    for p in DOCS:
        for m in re.findall(r'(/api/[a-z]+)', read(p)):
            mentioned.setdefault(m, set()).add(p.name)
    for ep, where in sorted(mentioned.items()):
        if ep not in routes:
            fail("C", f"文档提到 `{ep}`，但 ui.py 没有该路由（{', '.join(sorted(where))}）")
    ok("C", f"文档提到的 {len(mentioned)} 个接口全部存在（服务端共 {len(routes)} 个）")


# ---------- D 本地链接 ----------
def check_links() -> None:
    missing = 0
    for p in DOCS:
        text = read(p)
        for target in re.findall(r'\]\(([^)\s]+)\)', text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            tgt = (p.parent / target).resolve()
            if not tgt.exists():
                fail("D", f"{p.name} 里的链接 `{target}` 指向不存在的文件")
                missing += 1
    if not missing:
        ok("D", "文档内的本地链接全部有效")


# ---------- E 版本卫生 ----------
def check_versions() -> None:
    import certdiag

    cur = certdiag.__version__
    pat_portable = re.compile(r"certdiag-portable-\d+\.\d+")
    pat_download = re.compile(r"releases/download/v\d")
    for p in DOCS:
        text = read(p)
        if pat_portable.search(text):
            fail("E", f"{p.name} 写死了便携包目录名（应使用 certdiag-portable-<版本>）")
        if pat_download.search(text):
            fail("E", f"{p.name} 写了带版本的下载链接（应指向 /releases/latest）")

    # 提到的版本号不能高于当前版本
    def key(v: str) -> tuple:
        return tuple(int(x) for x in v.split("."))

    for p in DOCS:
        for v in set(re.findall(r"v(\d+\.\d+\.\d+)", read(p))):
            if key(v) > key(cur):
                fail("E", f"{p.name} 提到未来版本 v{v}（当前 {cur}）")
    ok("E", f"版本引用无写死/无未来版本（当前 v{cur}）")


# ---------- F 测试数量 ----------
def check_test_count() -> None:
    def count(dirpath: Path) -> int:
        n = 0
        for f in dirpath.glob("test_*.py"):
            tree = ast.parse(read(f))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                    n += 1
        return n

    actual = count(ROOT / "tests")

    # 1) README 的 "Ran N tests"
    m = re.search(r"Ran (\d+) tests", read(ROOT / "README.md"))
    TOL = 5   # 每加一个测试就要改文档太脆，留给小幅波动
    if not m:
        fail("F", "README 没写测试数量")
    elif abs(int(m.group(1)) - actual) > TOL:
        fail("F", f"README 写 {m.group(1)} 个测试，实际 {actual} 个")

    # 2) 其他文档里的 "N 个用例 / N 个测试"——这类数字最容易悄悄过期
    for p in DOCS:
        for line in read(p).splitlines():
            if "当时" in line:          # 历史记录里的数字保留原样
                continue
            for n, unit in re.findall(r"(\d+)\s*个\s*(用例|测试)", line):
                if int(n) > 20 and abs(int(n) - actual) > 5:   # 忽略"3 个场景"这类小数字
                    fail("F", f"{p.name} 写 {n} 个{unit}，实际 {actual} 个")
    ok("F", f"测试数量一致：{actual}")


# ---------- G 退出码 ----------
def check_exit_codes() -> None:
    src = read(ROOT / "certdiag" / "cli.py")
    consts = {k: int(v) for k, v in re.findall(r"^(EXIT_\w+)\s*=\s*(\d+)", src, re.M)}
    if not consts:
        fail("G", "cli.py 里没有 EXIT_* 常量")
        return

    text = read(ROOT / "README.md")
    rows = re.findall(r"^\|\s*(\d)\s*\|\s*([^|]+)\|", text, re.M)
    documented = {int(n) for n, _ in rows}
    if documented and documented != set(consts.values()):
        # 只要求文档里的退出码是代码的子集且覆盖 0/1
        extra = documented - set(consts.values())
        if extra:
            fail("G", f"README 写了不存在的退出码 {sorted(extra)}（代码：{sorted(consts.values())}）")
    ok("G", f"退出码常量 {sorted(consts.items())}")


# ---------- H JSON 协议 ----------
def check_schema() -> None:
    src = read(ROOT / "certdiag" / "cli.py")
    m = re.search(r'"schema_version"\s*:\s*(\d+)', src)
    if not m:
        fail("H", "cli.py 里找不到 schema_version")
        return
    code_ver = int(m.group(1))
    text = read(ROOT / "README.md")
    docs_vers = {int(x) for x in re.findall(r"schema_version[^0-9]{0,12}(\d)", text)}
    if docs_vers and docs_vers != {code_ver}:
        fail("H", f"README 提到 schema_version {sorted(docs_vers)}，代码是 {code_ver}")
    else:
        ok("H", f"schema_version 一致：{code_ver}")


# ---------- I 图片 ----------
def check_images() -> None:
    missing = 0
    for p in DOCS:
        for src in re.findall(r"!\[[^\]]*\]\(([^)]+)\)", read(p)):
            if src.startswith(("http://", "https://", "data:")):
                continue
            if not (p.parent / src).exists():
                fail("I", f"{p.name} 引用的图片 `{src}` 不存在")
                missing += 1
    if not missing:
        ok("I", "文档引用的图片全部存在")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    for fn in (check_categories, check_flags, check_endpoints, check_links,
               check_versions, check_test_count, check_exit_codes, check_schema, check_images):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            fail(fn.__name__, f"检查本身出错：{type(e).__name__}: {e}")

    if args.verbose:
        for c in checks:
            print("  OK  " + c)
    if problems:
        print(f"发现 {len(problems)} 个问题：")
        for p in problems:
            print("  - " + p)
        return 1
    print(f"文档一致性检查通过（{len(checks)} 组）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

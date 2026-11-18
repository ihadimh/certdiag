"""build_portable.py — 生成免安装便携版

思路：
    不重写成 C#，而是把官方 **embeddable Python**（约 11 MB）和项目代码打在一起。
    解压双击即用，不需要用户装 Python。

产物：
    dist/certdiag-portable-<ver>/
        runtime/            ← python-3.12.10-embed-amd64 解压内容
        certdiag/           ← 代码
        docs/ samples/ tools/
        verify.py  README.md  LICENSE
        双击启动.cmd         ← 无黑框开界面
        命令行诊断.cmd       ← 拖文件上来直接诊断
    dist/certdiag-portable-<ver>.zip

关键点：
    - embeddable 版有 python312._pth，它**屏蔽 site-packages 并接管 sys.path**，
      必须在里面加一行 ..，让项目根目录可被 import。
    - 用 pythonw.exe 启动界面（无控制台窗口）。
    - .cmd 必须 CRLF，否则 cmd 解析报错。
"""
from __future__ import annotations

import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
PY_VER = "3.12.10"
URL = f"https://www.python.org/ftp/python/{PY_VER}/python-{PY_VER}-embed-amd64.zip"

# 便携版只带运行所需的内容：构建/图标类工具留在仓库，不进分发包
COPY = ["certdiag", "docs", "samples", "tests",
        "verify.py", "README.md", "SECURITY.md", "LICENSE"]
SKIP_SUFFIX = {".pyc", ".exe", ".dll"}


def app_version() -> str:
    from certdiag import __version__
    return __version__


def fetch_runtime(cache: Path) -> Path:
    cache.parent.mkdir(parents=True, exist_ok=True)
    if cache.exists() and cache.stat().st_size > 1_000_000:
        print(f"[=] 复用缓存 {cache.name} ({cache.stat().st_size/1024/1024:.1f} MB)")
        return cache
    print(f"[+] 下载 embeddable Python {PY_VER} …")
    urllib.request.urlretrieve(URL, cache)
    print(f"    完成 {cache.stat().st_size/1024/1024:.1f} MB")
    return cache


def verify_runtime(runtime: Path) -> None:
    """校验解压出来的 python.exe 有没有有效的 Authenticode 签名。

    构建输入也要验：官方 zip 是 http 下载还是被中间人换过，只看域名判断不了。
    用本项目自己的 winverify 去问系统，失败就让构建停下来。
    """
    import sys

    sys.path.insert(0, str(ROOT))
    try:
        from certdiag.winverify import verify
    except Exception as e:  # noqa: BLE001
        print(f"[!] 跳过签名校验（模块不可用：{e}）")
        return

    exe = runtime / "python.exe"
    if not exe.exists():
        raise SystemExit("[x] runtime/python.exe 不存在，构建中止")

    r = verify(str(exe))
    if r.ok:
        who = (r.get("signer") or r.get("desc") or r.get("name") or "")
        print(f"[+] runtime/python.exe 签名有效（{who}）")
    else:
        raise SystemExit(
            f"[x] runtime/python.exe 签名校验失败：{r.get('name')} — {r.get('desc')}\n"
            "    构建已中止。请删除 dist/.cache 里的运行时重新下载。")


def patch_pth(runtime: Path) -> None:
    """embeddable 版靠 ._pth 决定 sys.path，必须把项目根目录加进去。"""
    pth = next(runtime.glob("python*._pth"), None)
    if pth is None:
        print("[!] 没找到 ._pth，跳过")
        return
    lines = [l for l in pth.read_text(encoding="utf-8").splitlines() if l.strip()]
    lines = [l for l in lines if l not in (".", "..")]
    # runtime 的上一级就是应用根目录
    lines.insert(0, "..")
    lines.insert(1, ".")
    pth.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] 已修正 {pth.name}: {lines}")


LAUNCH_UI = r"""@echo off
chcp 65001 >nul
cd /d "%~dp0"
start "" "%~dp0runtime\pythonw.exe" -m certdiag --ui
"""

LAUNCH_CLI = r"""@echo off
chcp 65001 >nul
cd /d "%~dp0"
if "%~1"=="" (
    echo   把文件或文件夹拖到本文件上，即可直接诊断
    echo   或运行 双击启动.cmd 打开图形界面
    echo.
    pause
    exit /b 0
)
"%~dp0runtime\python.exe" -m certdiag "%~1"
echo.
echo   按任意键关闭…
pause >nul
"""


def write_cmd(path: Path, text: str) -> None:
    path.write_text(text.replace("\n", "\r\n"), encoding="gbk", errors="replace")
    print(f"[+] {path.name}")


def copy_tree(src: Path, dst: Path) -> int:
    n = 0
    for p in src.rglob("*"):
        if not p.is_file():
            continue
        if "__pycache__" in p.parts or p.suffix in SKIP_SUFFIX:
            continue
        target = dst / p.relative_to(src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, target)
        n += 1
    return n


def main() -> int:
    ver = app_version()
    name = f"certdiag-portable-{ver}"
    out = DIST / name
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    zpath = fetch_runtime(DIST / ".cache" / f"python-{PY_VER}-embed-amd64.zip")

    runtime = out / "runtime"
    runtime.mkdir()
    with zipfile.ZipFile(zpath) as z:
        z.extractall(runtime)
    print(f"[+] runtime/ 解压完成（{len(list(runtime.iterdir()))} 个文件）")
    verify_runtime(runtime)
    patch_pth(runtime)

    total = 0
    for item in COPY:
        src = ROOT / item
        if not src.exists():
            print(f"[!] 跳过不存在的 {item}")
            continue
        if src.is_dir():
            total += copy_tree(src, out / item)
        else:
            shutil.copy2(src, out / item)
            total += 1
    print(f"[+] 复制 {total} 个项目文件")

    write_cmd(out / "双击启动.cmd", LAUNCH_UI)
    write_cmd(out / "命令行诊断.cmd", LAUNCH_CLI)

    zpkg = DIST / f"{name}.zip"
    if zpkg.exists():
        zpkg.unlink()
    with zipfile.ZipFile(zpkg, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(out.rglob("*")):
            if p.is_file():
                # 带上顶层目录，用户解压后是一个完整的文件夹而不是散落一堆
                z.write(p, Path(name) / p.relative_to(out))
    size = zpkg.stat().st_size / 1024 / 1024
    print(f"\n[✓] {zpkg}  ({size:.1f} MB)")
    print(f"[✓] 解压后目录：{out}")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())

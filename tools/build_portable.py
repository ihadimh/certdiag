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
# 控制台编码保护：英文 Windows 的 stdout 是 cp1252，print 中文会直接抛
# UnicodeEncodeError。这里只保证"不崩"，显示效果交给 chcp。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001
        pass

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

if not exist "%~dp0runtime\pythonw.exe" goto missing

set "URL=http://127.0.0.1:8765/"

rem 已经有实例在跑：直接开浏览器
powershell -NoProfile -Command "try{ if((Invoke-RestMethod '%URL%api/health' -TimeoutSec 2).ok){exit 0} }catch{}; exit 1" >nul 2>&1
if not errorlevel 1 goto open

start "" "%~dp0runtime\pythonw.exe" -m certdiag --ui --no-browser

for /l %%i in (1,1,20) do (
  powershell -NoProfile -Command "try{ if((Invoke-RestMethod '%URL%api/health' -TimeoutSec 1).ok){exit 0} }catch{}; exit 1" >nul 2>&1
  if not errorlevel 1 goto open
  timeout /t 1 >nul
)

echo.
echo   [错误] 界面没有在 20 秒内启动。
echo   请把本窗口截图发给作者。
pause
exit /b 1

:open
set "EDGE=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if exist "%EDGE%" (
  start "" "%EDGE%" --new-window "%URL%"
) else (
  start "" "%URL%"
)
echo.
echo   界面已启动：%URL%
echo   浏览器没弹出的话，手动打开上面这个地址。
timeout /t 3 >nul
exit /b 0

:missing
echo.
echo   [错误] 找不到运行时：
echo   %~dp0runtime\pythonw.exe
echo.
echo   当前目录：%CD%
echo.
echo   如果上面路径里带着 .zip\ 或 Temp\ 字样，说明你是在
echo   压缩包预览窗口里直接双击的，那个目录里当然没有 runtime。
echo.
echo   正确做法：右键压缩包 -> 全部解压缩，再进文件夹双击。
echo.
pause
exit /b 1
"""

LAUNCH_SHORTCUT = r"""@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist "%~dp0runtime\pythonw.exe" goto missing

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'certdiag 证书诊断.lnk')); $s.TargetPath = '%~dp0runtime\pythonw.exe'; $s.Arguments = '-m certdiag --ui'; $s.WorkingDirectory = '%~dp0'; $s.IconLocation = '%~dp0certdiag-seal.ico,0'; $s.Description = 'certdiag 证书诊断'; $s.Save(); Write-Host '' ; Write-Host '  已创建桌面快捷方式：certdiag 证书诊断'"

echo.
pause
exit /b

:missing
echo.
echo   [错误] 找不到运行时：
echo   %~dp0runtime\pythonw.exe
echo.
echo   请先把压缩包【完整解压】到一个文件夹，再运行本文件。
echo.
pause
exit /b 1
"""


LAUNCH_CLI = r"""@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist "%~dp0runtime\python.exe" goto missing
if "%~1"=="" goto usage

"%~dp0runtime\python.exe" -m certdiag "%~1"
echo.
echo   按任意键关闭...
pause >nul
exit /b

:usage
echo.
echo   把文件或文件夹【拖到本文件上】，即可直接诊断
echo   或双击「双击启动」打开图形界面
echo.
pause
exit /b 0

:missing
echo.
echo   [错误] 找不到运行时：
echo   %~dp0runtime\python.exe
echo.
echo   请先把压缩包【完整解压】到一个文件夹，再运行本文件。
echo.
pause
exit /b 1
"""


USAGE_TXT = r"""certdiag {ver} 便携版 · 使用说明
==================================================

一、怎么启动（必须先解压）
  1. 右键压缩包 → 全部解压缩（不要在压缩包预览窗口里直接双击里面的文件）
  2. 打开解压出的文件夹 certdiag-portable-{ver}
  3. 双击「双击启动」→ 浏览器会打开 http://127.0.0.1:8765
  4. 把 exe / dll 拖进窗口，或点「选择文件」

二、命令行用法
  方法 A：把文件或文件夹直接拖到「命令行诊断」图标上
  方法 B：在本文件夹里打开 PowerShell / CMD，运行：

      .\runtime\python.exe -m certdiag "C:\路径\程序.exe"
      .\runtime\python.exe -m certdiag "C:\路径\文件夹" --fail-on invalid
      .\runtime\python.exe -m certdiag "C:\路径\程序.exe" --revoke=auto

三、常用参数
  --revoke=off|cache|auto|online  吊销检查档位。默认 off，报告会明确写「未检查」
  --offline                       完全离线：不探测、不联网查吊销、不下载中间证书
  --no-probe                      只关闭网络探测
  --require-signature             把「无签名 / 无法验证」也判为失败（签名门禁用）
  --allow-private                 允许探测内网地址（默认禁止，防止证书里的地址引导内网访问）
  --json                          输出 JSON
  --ui --port 8765                启动图形界面并指定端口

四、退出码
  0 = 全部有效
  1 = 存在确定无效
  2 = 存在无法判定（网络/吊销查不到）
  3 = 运行出错（参数错误、文件不存在等）

五、自检（怀疑环境有问题时跑这个）
  .\runtime\python.exe verify.py
  .\runtime\python.exe -m unittest discover -s tests

六、常见问题
  Q: 双击提示「找不到运行时」
  A: 你是在压缩包预览里双击的，那个临时目录里没有 runtime。
     先完整解压，再进文件夹运行。

  Q: 双击「双击启动」没反应，浏览器也没开
  A: 可能已经有一个实例在跑了（8765 端口被占）。先直接访问
     http://127.0.0.1:8765 看看；要重启就先关掉旧的 pythonw 进程。

  Q: 结论写「未检查（--revoke=off）」
  A: 这是默认行为，不是错误。要看吊销状态就加 --revoke=auto。

  Q: 界面里没有吊销选项
  A: 命令行才有 --revoke，界面固定用默认 off。

七、安全说明
  只读诊断：不安装证书、不改注册表、不绕过签名校验、不上传任何文件。
  证书里的 CRL/OCSP 地址属于不可信输入，指向内网时默认不探测。
  详见同目录 SECURITY.md。
"""


def write_cmd(path: Path, text: str) -> None:
    path.write_text(text.replace("\n", "\r\n"), encoding="utf-8")
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
    write_cmd(out / "创建桌面快捷方式.cmd", LAUNCH_SHORTCUT)
    ico = ROOT / "docs" / "certdiag-seal.ico"
    if ico.exists():
        shutil.copy2(ico, out / "certdiag-seal.ico")
        print("[+] certdiag-seal.ico（快捷方式图标）")
    (out / "使用说明.txt").write_text(USAGE_TXT.replace("{ver}", ver), encoding="utf-8-sig")
    print("[+] 使用说明.txt")

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

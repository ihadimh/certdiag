"""set_icon.py — 把选定的方案做成最终 .ico 并应用到快捷方式与文件夹

用法：
    python tools/set_icon.py seal          # 亮红
    python tools/set_icon.py seal_matte    # 暗红磨砂
    python tools/set_icon.py seal_teal     # 青绿封蜡

踩过的坑（重要）：
    1. Windows 图标缓存是**按文件路径**索引的。内容改了但路径不变，
       缓存不会重新加载，桌面看起来"没变化"。
       解法：文件名带上方案名（certdiag-seal.ico / certdiag-seal_teal.ico），
       路径一变缓存必然失效。
    2. desktop.ini 必须用 UTF-16 (Unicode) 写，UTF-8 带 BOM 资源管理器不认。
    3. 改完要通知 shell 刷新（SHChangeNotify），否则仍显示旧图。
"""

from __future__ import annotations

import ctypes
import subprocess
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
sys.path.insert(0, str(ROOT / "tools"))

from make_icons import ICONS  # noqa: E402

SIZES = [16, 24, 32, 48, 64, 128, 256]
DESKTOP = Path.home() / "Desktop"
APP_DIR = DESKTOP / "certdiag"
LNK = DESKTOP / "certdiag 证书诊断.lnk"

SHCNE_ASSOCCHANGED = 0x08000000
SHCNF_IDLIST = 0x0000


def refresh_shell() -> None:
    """通知资源管理器重新读取图标。"""
    try:
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
    except Exception:  # noqa: BLE001
        pass
    subprocess.run(["ie4uinit.exe", "-show"], check=False)


def build(key: str) -> Path:
    fn = dict((k, f) for k, _, f in ICONS)[key]
    img = fn()
    images = [img.resize((s, s), 1) for s in SIZES]   # 1 = LANCZOS

    # 路径带方案名 -> 图标缓存不会命中旧记录
    ico = ROOT / "docs" / f"certdiag-{key}.ico"
    images[-1].save(ico, format="ICO", sizes=[(s, s) for s in SIZES])
    images[-1].save(ROOT / "docs" / "icon-256.png")
    print(f"[+] {ico.name}  ({ico.stat().st_size} B)  方案：{key}")
    return ico


def apply(key: str, ico: Path) -> None:
    if not APP_DIR.exists():
        print("[!] 桌面没有 certdiag 目录，跳过")
        return

    # 只保留当前方案的 ico，避免目录里堆一串
    for old in APP_DIR.glob("certdiag*.ico"):
        try:
            old.unlink()
        except OSError:
            pass
    target = APP_DIR / ico.name
    target.write_bytes(ico.read_bytes())

    # 快捷方式
    ps = ("$ws = New-Object -ComObject WScript.Shell; "
          f"$l = $ws.CreateShortcut('{LNK}'); "
          f"$l.IconLocation = '{target},0'; "
          "$l.Save()")
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=False)

    # 文件夹图标：desktop.ini 必须是 UTF-16
    ini_path = APP_DIR / "desktop.ini"
    try:
        subprocess.run(["attrib", "-R", "-S", str(ini_path)], check=False,
                       capture_output=True)
        subprocess.run(["attrib", "-R", str(APP_DIR)], check=False, capture_output=True)
    except Exception:  # noqa: BLE001
        pass
    content = ("[.ShellClassInfo]\r\n"
               f"IconResource={target},0\r\n"
               "InfoTip=Windows 代码签名与证书链诊断工具\r\n")
    ini_path.write_text(content, encoding="utf-16")
    subprocess.run(["attrib", "+R", "+S", str(ini_path)], check=False, capture_output=True)

    # 关键：翻转文件夹的只读属性，逼资源管理器重读 desktop.ini
    # （只写不翻，图标不会变；这是最容易漏的一步）
    subprocess.run(["attrib", "-R", str(APP_DIR)], check=False, capture_output=True)
    subprocess.run(["attrib", "+R", str(APP_DIR)], check=False, capture_output=True)

    refresh_shell()
    print(f"[+] 已应用：快捷方式 + 文件夹（{target.name}）")


def main(argv: list[str]) -> int:
    keys = [k for k, _, _ in ICONS]
    key = argv[1] if len(argv) > 1 else "seal"
    if key not in keys:
        print("可选：" + ", ".join(keys))
        return 2
    apply(key, build(key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

# -*- coding: utf-8 -*-
"""make_test_samples.py — 生成两份**测试样本**，用于演示"签名有效"与"文件被改过"

这个脚本干什么：
    1. 复制一个已签名的可执行文件（默认 Git 自带的 git.exe）→ signed_ok.exe
    2. 在副本的 .text 段翻转一个字节 → tampered.exe

为什么需要篡改样本：
    要证明工具能识别"文件被改过"，就必须有一个真的被改过的文件。
    Authenticode 的哈希覆盖整个文件，改一个字节签名就会失效。

安全说明（重要）：
    - 只操作**副本**，源文件原样不动
    - 不联网、不下载、不写系统目录、不改注册表
    - 生成的 .exe 只在 samples/ 下，且已被 .gitignore 排除，不进仓库
    - tampered.exe 是损坏文件，仅用于测试，不应运行
"""
from __future__ import annotations

import shutil
import struct
import sys
from pathlib import Path

# 先修控制台编码：英文版 Windows 的控制台是 cp1252，直接打印中文/箭头会崩
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    from certdiag.cli import fix_console

    fix_console()
except Exception:  # noqa: BLE001
    pass

OUT = Path(__file__).parent
# 只选"有嵌入式签名"的文件：篡改后才会出现 HashMismatch。
# 若选仅目录签名的文件，篡改后只会变成 NotSigned，演示效果不典型。
CANDIDATES = [
    r"C:\Program Files\Git\cmd\git.exe",
    r"C:\Program Files\Git\usr\bin\git.exe",
]


def find_source() -> Path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from certdiag.winverify import verify

    # 1) 常见 git 路径
    for c in CANDIDATES:
        p = Path(c)
        if p.exists() and verify(str(p)).get("hresult") == 0:
            return p

    # 2) 便携包自带的 python.exe（PSF 签名，嵌入式）
    p = Path(sys.executable)
    if p.exists() and verify(str(p)).get("hresult") == 0:
        return p

    # 3) 在 System32 里找第一个有嵌入式签名的 exe（最多 120 个）
    import glob
    for c in sorted(glob.glob(r"C:\Windows\System32\*.exe"))[:120]:
        try:
            if verify(c).get("hresult") == 0:
                return Path(c)
        except Exception:  # noqa: BLE001
            continue

    raise SystemExit("找不到带嵌入式签名的源文件（可装 Git 后重试）")


def pe_section_offset(data: bytes, name: bytes) -> int | None:
    """返回指定节的文件偏移（用于安全地改一个字节）。"""
    if data[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return None
    coff = pe + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    sec = opt + opt_size
    for i in range(nsec):
        off = sec + i * 40
        sname = data[off:off + 8].rstrip(b"\0")
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
        if sname == name and raw_size > 64:
            return raw_ptr + raw_size // 2
    return None


def main() -> int:
    src = find_source()
    ok = OUT / "signed_ok.exe"
    bad = OUT / "tampered.exe"

    shutil.copy2(src, ok)
    print(f"[+] {ok.name}  ← {src}")

    data = bytearray(ok.read_bytes())
    off = pe_section_offset(data, b".text")
    if off is None:
        raise SystemExit("无法定位 .text 段")
    old = data[off]
    data[off] = old ^ 0xFF          # 翻转一个字节
    bad.write_bytes(bytes(data))
    print(f"[+] {bad.name}  ← 修改偏移 0x{off:X}（{old:#04x} → {data[off]:#04x}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""pe.py — 最小 PE 结构探测

为什么需要它：
    Get-AuthenticodeSignature 对"打不开的文件"只返回 UnknownError 或 NotSigned。
    直接按这个状态归因，会把**损坏的 exe** 说成"这个文件类型没有签名概念"，
    把**被截断的程序**说成"没有签名"——两者都是错的。

这里只做三件事，不解析节表、不碰资源：
    1. 有没有 MZ 头
    2. 有没有 PE\\0\\0 签名
    3. 安全目录（证书表）的偏移+长度是否落在文件内 —— 落不下就是被截断
"""
from __future__ import annotations

import struct

# 只有这些扩展名才"应该"是 PE；.ps1/.msi/.cat 是别的签名形态
PE_EXTS = {".exe", ".dll", ".sys", ".efi", ".ocx", ".cpl", ".scr", ".drv"}


def looks_like_pe_name(path: str) -> bool:
    import os

    return os.path.splitext(str(path))[1].lower() in PE_EXTS


def inspect(path: str) -> dict:
    """返回 {is_pe, truncated, reason}；读不了也不抛异常。"""
    out = {"is_pe": False, "truncated": False, "reason": ""}
    try:
        size = __import__("os").path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(0x40)
            if len(head) < 0x40 or head[:2] != b"MZ":
                out["reason"] = "没有 MZ 头，不是 PE 文件"
                return out

            e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            if e_lfanew <= 0 or e_lfanew + 24 > size:
                out["truncated"] = True
                out["reason"] = "PE 头偏移越界（文件可能被截断）"
                return out

            fh.seek(e_lfanew)
            sig = fh.read(4)
            if sig != b"PE\0\0":
                out["reason"] = "缺少 PE 签名，不是有效程序"
                return out

            out["is_pe"] = True

            coff = fh.read(20)          # IMAGE_FILE_HEADER
            opt_size = struct.unpack_from("<H", coff, 16)[0] if len(coff) >= 20 else 0
            opt = fh.read(opt_size)
            if len(opt) < 2:
                out["truncated"] = True
                out["reason"] = "可选头缺失（文件被截断）"
                return out

            magic = struct.unpack_from("<H", opt, 0)[0]
            dd = 96 if magic == 0x10B else 112      # PE32 / PE32+
            if len(opt) < dd + 8 * 5:
                out["truncated"] = True
                out["reason"] = "数据目录不完整（文件被截断）"
                return out

            cert_off, cert_size = struct.unpack_from("<II", opt, dd + 8 * 4)
            if cert_off and cert_size:
                if cert_off + cert_size > size:
                    out["truncated"] = True
                    out["reason"] = "证书表超出文件末尾（文件被截断）"
    except OSError as e:
        out["reason"] = f"无法读取：{e}"
    except struct.error as e:
        out["reason"] = f"PE 结构异常：{e}"
    return out

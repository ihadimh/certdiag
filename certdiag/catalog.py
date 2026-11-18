"""catalog.py — 目录签名（Catalog / .cat）检测

背景：
    大量 Windows 系统文件没有"嵌入式签名"——它们的签名不在 PE 文件里，
    而是被收进一个 .cat 目录文件中（记录文件名 + 哈希 + 签名）。
    Get-AuthenticodeSignature 对这类文件返回 NotSigned，
    于是很容易被误判成"文件没签名/被篡改"。

做法（不重写密码学逻辑，只调用系统 API）：
    1. CryptCATAdminAcquireContext[2]  取得目录管理员上下文
    2. CryptCATAdminCalcHashFromFileHandle[2]  计算文件哈希（即 member tag）
    3. CryptCATAdminEnumCatalogFromHash  反查包含该哈希的 .cat
    4. 用现有的 collect() 验证 .cat 自身的签名是否有效

兼容性：
    *2 系列函数（Win8+，可指定哈希算法）在本机可能不存在，
    因此所有调用都先检测导出是否存在，不存在则退回旧接口。

边界：
    - 只做"查找 + 读取 + 验证 .cat 的签名"，不修改任何目录数据库
    - 找不到目录时返回 found=False，不猜测
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path

_crypt32 = ctypes.WinDLL("wintrust", use_last_error=True)  # CryptCATAdmin* 由 wintrust 导出
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

HCATADMIN = wintypes.HANDLE
HCATINFO = wintypes.HANDLE

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("wszCatalogFile", wintypes.WCHAR * 260),
    ]


def _has(name: str) -> bool:
    try:
        getattr(_crypt32, name)
        return True
    except AttributeError:
        return False


HAS_CTX2 = _has("CryptCATAdminAcquireContext2")
HAS_HASH2 = _has("CryptCATAdminCalcHashFromFileHandle2")


def _bind():
    # 旧接口一定存在
    _crypt32.CryptCATAdminAcquireContext.argtypes = [
        ctypes.POINTER(HCATADMIN), ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD]
    _crypt32.CryptCATAdminAcquireContext.restype = wintypes.BOOL

    _crypt32.CryptCATAdminCalcHashFromFileHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD]
    _crypt32.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL

    _crypt32.CryptCATAdminEnumCatalogFromHash.argtypes = [
        HCATADMIN, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(HCATINFO)]
    _crypt32.CryptCATAdminEnumCatalogFromHash.restype = HCATINFO

    _crypt32.CryptCATAdminReleaseCatalogContext.argtypes = [HCATADMIN, HCATINFO, wintypes.DWORD]
    _crypt32.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL

    _crypt32.CryptCATAdminReleaseContext.argtypes = [HCATADMIN, wintypes.DWORD]
    _crypt32.CryptCATAdminReleaseContext.restype = wintypes.BOOL

    _crypt32.CryptCATCatalogInfoFromContext.argtypes = [
        HCATINFO, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
    _crypt32.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    if HAS_CTX2:
        _crypt32.CryptCATAdminAcquireContext2.argtypes = [
            ctypes.POINTER(HCATADMIN), ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.c_void_p, wintypes.DWORD]
        _crypt32.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
    if HAS_HASH2:
        _crypt32.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
            HCATADMIN, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD]
        _crypt32.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL


_bind()


class CatalogResult(dict):
    """字典形式返回，方便直接进报告。"""

    @property
    def found(self) -> bool:
        return bool(self.get("catalog_path"))


def _acquire(hash_alg: str | None):
    """返回 (admin_handle, 使用的算法标记)；失败抛 OSError。"""
    admin = HCATADMIN()
    if HAS_CTX2:
        if _crypt32.CryptCATAdminAcquireContext2(
                ctypes.byref(admin), None, hash_alg, None, 0):
            return admin, hash_alg
    if _crypt32.CryptCATAdminAcquireContext(ctypes.byref(admin), None, None, 0):
        return admin, None   # 旧接口固定 SHA1
    raise OSError(ctypes.get_last_error(), "CryptCATAdminAcquireContext 失败")


def _hash_file(admin, handle, alg: str | None) -> bytes:
    size = wintypes.DWORD(0)
    if alg and HAS_HASH2:
        _crypt32.CryptCATAdminCalcHashFromFileHandle2(
            admin, handle, ctypes.byref(size), None, 0)
    else:
        _crypt32.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size), None, 0)
    if not size.value:
        raise OSError(ctypes.get_last_error(), "计算文件哈希失败")

    buf = (ctypes.c_ubyte * size.value)()
    if alg and HAS_HASH2:
        ok = _crypt32.CryptCATAdminCalcHashFromFileHandle2(
            admin, handle, ctypes.byref(size), buf, 0)
    else:
        ok = _crypt32.CryptCATAdminCalcHashFromFileHandle(
            handle, ctypes.byref(size), buf, 0)
    if not ok:
        raise OSError(ctypes.get_last_error(), "计算文件哈希失败")
    return bytes(buf[:size.value])


def find_catalog(path: str | os.PathLike) -> CatalogResult:
    """查找覆盖该文件的 .cat。找不到时 found=False，不抛异常。"""
    p = str(Path(path))
    result = CatalogResult(catalog_path=None, member_tag=None,
                           hash_alg=None, error=None)
    if not os.path.isfile(p):
        result["error"] = "文件不存在"
        return result

    handle = _kernel32.CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, None,
                                   OPEN_EXISTING, 0, None)
    if not handle or handle == INVALID_HANDLE_VALUE:
        result["error"] = f"无法打开文件（错误码 {ctypes.get_last_error()}）"
        return result

    admin = None
    cat_info = None
    try:
        admin, alg = _acquire("SHA256")
        try:
            digest = _hash_file(admin, handle, alg)
        except OSError:
            # 老目录用 SHA1 计算哈希，换一次再试
            _crypt32.CryptCATAdminReleaseContext(admin, 0)
            admin, alg = _acquire(None)
            digest = _hash_file(admin, handle, alg)

        buf = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
        cat_info = _crypt32.CryptCATAdminEnumCatalogFromHash(
            admin, buf, len(digest), 0, None)
        if not cat_info:
            return result

        info = CATALOG_INFO()
        info.cbStruct = ctypes.sizeof(CATALOG_INFO)
        if _crypt32.CryptCATCatalogInfoFromContext(cat_info, ctypes.byref(info), 0):
            result["catalog_path"] = info.wszCatalogFile
            result["member_tag"] = digest.hex().upper()
            result["hash_alg"] = alg or "SHA1"
    except OSError as e:
        result["error"] = str(e)
    finally:
        if cat_info:
            _crypt32.CryptCATAdminReleaseCatalogContext(admin, cat_info, 0)
        if admin:
            _crypt32.CryptCATAdminReleaseContext(admin, 0)
        _kernel32.CloseHandle(handle)
    return result


def describe(cat: dict) -> str:
    if not cat or not cat.get("catalog_path"):
        return "未找到覆盖该文件的目录（catalog）"
    return f"由目录签名覆盖：{cat['catalog_path']}（{cat.get('hash_alg')}）"

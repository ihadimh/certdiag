"""winverify.py — 直接调用 WinVerifyTrust，拿到精确 HRESULT

为什么需要它：
    Get-AuthenticodeSignature 只给出 `Valid / NotTrusted / HashMismatch` 这类粗粒度状态，
    而系统底层返回的是 HRESULT，能区分"证书被吊销""显式不信任""哈希不符"等具体原因。
    例如 0x800B010D（CRYPT_E_REVOCATION_OFFLINE）在 PowerShell 里常常只表现为
    `NotTrusted` + 一个模糊的 StatusMessage。

参数选择（与系统默认行为有意不同）：
    - WTD_UI_NONE            不弹任何对话框
    - WTD_REVOKE_NONE        不在本函数内做吊销检查——吊销由 probe.py 单独做，
                             避免一次调用卡在网络上几十秒
    - WTD_CACHE_ONLY_URL_RETRIEVAL（离线模式）只查本地缓存，不发网络请求

只读：不修改信任库，不写任何文件。
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

_wintrust = ctypes.WinDLL("wintrust", use_last_error=True)

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_REVOKE_WHOLECHAIN = 1
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x00000010
WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000080
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.POINTER(GUID))]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pUnion", ctypes.c_void_p),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


_wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
_wintrust.WinVerifyTrust.restype = wintypes.LONG

# HRESULT → (短名, 中文说明)
CODES: dict[int, tuple[str, str]] = {
    0x00000000: ("S_OK", "签名有效"),
    0x800B0100: ("TRUST_E_NOSIGNATURE", "文件没有签名（或签名格式不受支持）"),
    0x800B0001: ("TRUST_E_PROVIDER_UNKNOWN", "未知的信任提供程序"),
    0x800B0003: ("TRUST_E_SUBJECT_FORM_UNKNOWN", "签名主体格式未知"),
    0x800B0004: ("TRUST_E_SUBJECT_NOT_TRUSTED", "签名主体不被信任"),
    0x800B0101: ("CERT_E_EXPIRED", "证书已过期"),
    0x800B0107: ("CERT_E_ISSUERCHAINING", "颁发者链构建失败"),
    0x800B0109: ("CERT_E_UNTRUSTEDROOT", "根证书不受信任"),
    0x800B010A: ("CERT_E_CHAINING", "无法构建证书链"),
    0x800B010C: ("CERT_E_REVOKED", "证书已被吊销"),
    0x800B010D: ("CRYPT_E_REVOCATION_OFFLINE", "吊销状态无法获取（离线或不可达）"),
    0x800B010E: ("CERT_E_REVOCATION_FAILURE", "吊销检查失败"),
    0x800B0111: ("TRUST_E_EXPLICIT_DISTRUST", "该证书被显式标记为不信任"),
    0x80096010: ("TRUST_E_BAD_DIGEST", "文件内容与签名不匹配"),
    0x800B010B: ("TRUST_E_FAIL", "通用验证失败"),
}


class VerifyResult(dict):
    @property
    def ok(self) -> bool:
        return self.get("hresult") == 0


def verify(path: str, offline: bool = False, revoke: str = "off") -> VerifyResult:
    """返回 {hresult, hex, name, desc, error?}；调用失败时 error 有原因。"""
    result = VerifyResult(hresult=None, hex=None, name=None, desc=None, error=None)
    info = WINTRUST_FILE_INFO()
    info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    info.pcwszFilePath = str(path)
    info.hFile = None
    info.pgKnownSubject = None

    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = WTD_UI_NONE
    # revoke: off / cache / online（auto 由调用方先降级成 off 或 online）
    data.fdwRevocationChecks = WTD_REVOKE_NONE if revoke == "off" else WTD_REVOKE_WHOLECHAIN
    data.dwUnionChoice = WTD_CHOICE_FILE
    data.pUnion = ctypes.cast(ctypes.pointer(info), ctypes.c_void_p)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    if revoke == "off":
        data.dwProvFlags = WTD_REVOCATION_CHECK_NONE
    else:
        data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
    if offline or revoke == "cache":
        # cache 档：只查本地缓存，不发网络请求
        data.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL

    try:
        ret = _wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                                       ctypes.byref(data))
        hr = ret & 0xFFFFFFFF
        name, desc = CODES.get(hr, ("UNKNOWN", f"未收录的 HRESULT（0x{hr:08X}）"))
        result.update(hresult=hr, hex=f"0x{hr:08X}", name=name, desc=desc)
    except OSError as e:
        result["error"] = str(e)
    finally:
        # 释放状态数据
        data.dwStateAction = WTD_STATEACTION_CLOSE
        try:
            _wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                                     ctypes.byref(data))
        except OSError:
            pass
    return result


def explain(hresult: int | None) -> str:
    if hresult is None:
        return ""
    name, desc = CODES.get(hresult, ("UNKNOWN", "未收录"))
    return f"0x{hresult:08X} {name}：{desc}"

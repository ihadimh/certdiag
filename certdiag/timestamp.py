"""timestamp.py — 验证 Authenticode 时间戳令牌

为什么需要它：
    "证书过期但签名仍有效"这个结论，取决于时间戳是否**真的可信**。
    只看到"有时间戳"是不够的——令牌本身可能损坏、可能不是合法 TSA 签的。

做法（不做 ASN.1 手写解析，借 .NET 的 SignedCms）：
    1. 从 PE 安全目录取出 PKCS#7 blob
    2. SignedCms.Decode → CheckSignature(仅验签) 确认文件签名本身完好
    3. 遍历未认证属性，找到时间戳令牌（OID 1.3.6.1.4.1.311.3.3.1 / ...2.4.1）
    4. 把令牌当作一个独立的 SignedCms 再 Decode + CheckSignature
       → 通过就说明"这个时间点是某个 TSA 签发的且未被篡改"
    5. 取 TSA 证书的 subject 与有效期

边界：
    - 只验令牌签名与 TSA 证书信息，不做完整信任链与吊销检查（那是 winverify 的事）
    - 拿不到任何信息时返回 ok=False 并带 error，调用方据此降级为 unknown
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile

MAX_PARSE_BYTES = 512 * 1024 * 1024  # 512 MB
from pathlib import Path

from .psworker import hidden_kwargs

PS_SCRIPT = r"""
param([string]$Path)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

$out = [ordered]@{
    path = $Path; has_signature = $false; signature_ok = $false
    has_token = $false; token_ok = $false; token_oid = $null
    has_legacy_countersignature = $false; has_nested_signature = $false
    tsa_subject = $null; tsa_not_before = $null; tsa_not_after = $null
    error = $null
}

try {
    $b = [System.IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 0x40 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) { throw "不是 PE 文件" }
    $pe = [System.BitConverter]::ToInt32($b, 0x3C)
    $magic = [System.BitConverter]::ToUInt16($b, $pe + 24)
    if ($magic -eq 0x20B) { $dd = $pe + 24 + 112 + 4 * 8 }
    elseif ($magic -eq 0x10B) { $dd = $pe + 24 + 96 + 4 * 8 }
    else { throw "未知的 PE 格式" }

    $certOff = [System.BitConverter]::ToUInt32($b, $dd)
    $certSize = [System.BitConverter]::ToUInt32($b, $dd + 4)
    if ($certOff -eq 0 -or $certSize -eq 0) { throw "没有嵌入式签名" }

    # 不可信输入，所有偏移都要对着文件长度核对一遍，避免越界读取
    if ($certOff + 8 -gt $b.Length) { throw "签名目录偏移越界" }
    if ($certSize -lt 8 -or $certOff + $certSize -gt $b.Length) { throw "签名目录长度越界" }

    $len = [System.BitConverter]::ToUInt32($b, $certOff)
    if ($len -lt 8) { throw "WIN_CERTIFICATE 长度非法" }
    if ($len -gt $certSize) { throw "WIN_CERTIFICATE 长度超过签名目录声明的大小" }
    if ($len -gt $b.Length) { throw "WIN_CERTIFICATE 长度超过文件大小" }
    $out.has_signature = $true

    $p7 = New-Object byte[] ($len - 8)
    [Array]::Copy($b, $certOff + 8, $p7, 0, $len - 8)

    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $cms.Decode($p7)
    try { $cms.CheckSignature($true); $out.signature_ok = $true }
    catch { $out.error = "签名校验失败：$($_.Exception.Message)" }

    # OID 说明（别搞混）：
    #   1.3.6.1.4.1.311.3.3.1   RFC3161 时间戳令牌（本函数处理的对象）
    #   1.2.840.113549.1.9.6   传统 PKCS#9 countersignature（另一种时间戳机制）
    #   1.3.6.1.4.1.311.2.4.1  嵌套签名 szOID_NESTED_SIGNATURE —— 不是时间戳！
    foreach ($ua in $cms.SignerInfos[0].UnsignedAttributes) {
        if ($ua.Oid.Value -eq '1.2.840.113549.1.9.6') {
            $out.has_legacy_countersignature = $true
            continue
        }
        if ($ua.Oid.Value -eq '1.3.6.1.4.1.311.2.4.1') {
            $out.has_nested_signature = $true
            continue
        }
        if ($ua.Oid.Value -eq '1.3.6.1.4.1.311.3.3.1') {
            $out.has_token = $true
            $out.token_oid = $ua.Oid.Value
            $ts = New-Object System.Security.Cryptography.Pkcs.SignedCms
            $ts.Decode($ua.Values[0].RawData)
            try { $ts.CheckSignature($true); $out.token_ok = $true }
            catch { $out.error = "时间戳令牌校验失败：$($_.Exception.Message)" }
            $tsa = $ts.SignerInfos[0].Certificate
            if ($tsa) {
                $out.tsa_subject = $tsa.Subject
                $out.tsa_not_before = $tsa.NotBefore.ToString('yyyy-MM-ddTHH:mm:ss')
                $out.tsa_not_after = $tsa.NotAfter.ToString('yyyy-MM-ddTHH:mm:ss')
            }
            break
        }
    }
}
catch { $out.error = $_.Exception.Message }

$out | ConvertTo-Json -Compress
"""


class TimestampResult(dict):
    @property
    def verified(self) -> bool:
        return bool(self.get("token_ok"))

    def describe(self) -> str:
        if self.get("error") and not self.get("has_token"):
            return f"时间戳核实失败：{str(self['error'])[:80]}"
        if self.get("token_ok"):
            tsa = (self.get("tsa_subject") or "").split(",")[0]
            return f"时间戳令牌验证通过（TSA：{tsa}）"
        if self.get("has_token"):
            return "存在时间戳令牌，但令牌签名校验未通过"
        return "没有时间戳"


def _powershell() -> str:
    """时间戳解析依赖 .NET Framework 的 System.Security.Pkcs，
    Windows PowerShell 5.1 自带；pwsh 下可能拿不到，失败会降级。"""
    from shutil import which

    for name in ("powershell.exe", "powershell"):
        p = which(name)
        if p:
            return p
    for name in ("pwsh.exe", "pwsh"):
        p = which(name)
        if p:
            return p
    raise RuntimeError("未找到 PowerShell")


def verify(path: str | os.PathLike, timeout: float = 30.0) -> TimestampResult:
    p = str(Path(path))
    result = TimestampResult(has_signature=False, signature_ok=False,
                             has_token=False, token_ok=False, error=None)
    if not os.path.isfile(p):
        result["error"] = "文件不存在"
        return result

    try:
        ps = _powershell()
    except RuntimeError as e:
        result["error"] = str(e)
        return result

    # 解析会把整个文件读进内存；对超大文件先设上限，避免扫描时被单个文件拖垮
    try:
        size = os.path.getsize(p)
    except OSError as e:
        result["error"] = f"无法读取文件大小：{e}"
        return result
    if size > MAX_PARSE_BYTES:
        result["error"] = (f"文件过大（{size // 1024 // 1024} MB），"
                           f"跳过时间戳解析（上限 {MAX_PARSE_BYTES // 1024 // 1024} MB）")
        return result

    fd, script = tempfile.mkstemp(prefix="certdiag_ts_", suffix=".ps1")
    try:
        # 必须带 BOM：PowerShell 5.1 会把无 BOM 的 UTF-8 当 ANSI，中文注释会截断语法
        with os.fdopen(fd, "w", encoding="utf-8-sig") as fh:
            fh.write(PS_SCRIPT)
        proc = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", script, "-Path", p],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, **hidden_kwargs())
        line = (proc.stdout or "").strip().splitlines()
        if not line:
            result["error"] = (proc.stderr or "无输出").strip()[:300]
            return result
        data = json.loads(line[-1])
        result.update({k: v for k, v in data.items() if k != "path"})
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            os.unlink(script)
        except OSError:
            pass
    return result

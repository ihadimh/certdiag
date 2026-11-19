"""collect.py — 采集层：获取签名信息与证书链（只读，不改系统）

两条路径：
    1. 常驻 worker（psworker.PowerShellWorker）—— 默认，单次采集 10~50 ms
    2. 一次性 subprocess —— worker 不可用时的兜底，单次约 1.2 s

为什么用 PowerShell 而不是自己解析 PE：
    .NET 的 Get-AuthenticodeSignature 已经封装了链构建等细节，
    自己重写容易在时间戳、目录签名等边界上出错。
    采集层只负责"如实取数据"，判断逻辑在 attrib.py，便于单元测试。
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
from pathlib import Path

from .psworker import PowerShellWorker, hidden_kwargs

PS_SCRIPT = r"""
param([string]$Path, [string]$Out, [string]$Revoke = 'NoCheck', [string]$Offline = 'false')

$ErrorActionPreference = 'Stop'
$result = [ordered]@{
  path = $null; exists = $false; size = 0; sha256 = $null
  status = $null; status_message = $null
  signer = $null; signer_expired = $false; timestamper = $null
  chain = $null; crl_ocsp_urls = @(); error = $null
}

try {
  if (-not (Test-Path -LiteralPath $Path)) { throw "文件不存在：$Path" }
  $item = Get-Item -LiteralPath $Path
  $result.path = $item.FullName
  $result.exists = $true
  $result.size = $item.Length
  $result.sha256 = $null
  try { $result.sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }
  catch {
    try {
      $sha = [System.Security.Cryptography.SHA256]::Create()
      $fs = [System.IO.File]::OpenRead($item.FullName)
      try { $result.sha256 = ([System.BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '') }
      finally { $fs.Dispose(); $sha.Dispose() }
    } catch { }
  }

  $sig = Get-AuthenticodeSignature -LiteralPath $item.FullName
  $result.status = $sig.Status.ToString()
  $result.status_message = $sig.StatusMessage

  $cert = $sig.SignerCertificate
  if ($cert) {
    $result.signer = [ordered]@{
      subject    = $cert.Subject
      issuer     = $cert.Issuer
      thumbprint = $cert.Thumbprint
      serial     = $cert.SerialNumber
      not_before = $cert.NotBefore.ToString('yyyy-MM-ddTHH:mm:ssK')
      not_after  = $cert.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssK')
      version    = $cert.Version
    }
    $result.signer_expired = ($cert.NotAfter -lt (Get-Date))

    if ($sig.TimeStamperCertificate) {
      $ts = $sig.TimeStamperCertificate
      $result.timestamper = [ordered]@{
        subject    = $ts.Subject
        thumbprint = $ts.Thumbprint
        not_after  = $ts.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssK')
      }
    }

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::$Revoke
  # DisableCertificateDownloads 只在 .NET Core / 新版上有；PS 5.1 (Framework 4.8) 没有这个属性，
  # 直接赋值会抛异常并让整个采集失败。这里先探测是否存在，并把结果写进报告。
  if ($Offline -eq 'true' -and ($chain.ChainPolicy.PSObject.Properties.Name -contains 'DisableCertificateDownloads')) {
    $chain.ChainPolicy.DisableCertificateDownloads = $true
    $result.aia_downloads_disabled = $true
  } else {
    $result.aia_downloads_disabled = $false
  }
    $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
    $built = $chain.Build($cert)

    $elements = @()
    $urls = New-Object System.Collections.ArrayList
    foreach ($el in $chain.ChainElements) {
      $st = @()
      foreach ($s in $el.ChainElementStatus) {
        $st += [ordered]@{ status = $s.Status.ToString(); info = $s.StatusInformation }
      }
      $elements += [ordered]@{
        subject    = $el.Certificate.Subject
        issuer     = $el.Certificate.Issuer
        thumbprint = $el.Certificate.Thumbprint
        not_before = $el.Certificate.NotBefore.ToString('yyyy-MM-ddTHH:mm:ssK')
        not_after  = $el.Certificate.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssK')
        status     = $st
      }
      foreach ($ext in $el.Certificate.Extensions) {
        try {
          $txt = $ext.Format($false)
          if ($txt -match 'https?://') {
            foreach ($m in [regex]::Matches($txt, 'https?://[^\s",;<>\)\]]+')) {
              if (-not $urls.Contains($m.Value)) { [void]$urls.Add($m.Value) }
            }
          }
        } catch { }
      }
    }

    $cs = @()
    foreach ($s in $chain.ChainStatus) {
      $cs += [ordered]@{ status = $s.Status.ToString(); info = $s.StatusInformation }
    }

    $result.chain = [ordered]@{
      built = [bool]$built
      elements = $elements
      chain_status = $cs
    }
    $result.crl_ocsp_urls = @($urls)
  }
}
catch {
  $result.error = $_.Exception.Message
}

$json = $result | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding($false)))
"""

_worker: PowerShellWorker | None = None
_worker_lock = threading.Lock()
_use_worker = True
_stats = {"worker_calls": 0, "subprocess_calls": 0, "worker_fallbacks": 0}


def _find_powershell() -> str:
    from shutil import which
    # 优先 pwsh：从 PowerShell 7 的进程里启动 powershell.exe(5.1) 时，
    # 子进程会继承 PS7 的 PSModulePath，导致 5.1 加载不了自己的模块
    # （Get-AuthenticodeSignature 会报 module could not be loaded）。
    for name in ("pwsh.exe", "pwsh", "powershell.exe", "powershell"):
        p = which(name)
        if p:
            return p
    raise RuntimeError("未找到 PowerShell，无法采集签名信息")


def _collect_subprocess(path: str, timeout: int = 60, revoke: str = "NoCheck",
                        offline: bool = False) -> dict:
    _stats["subprocess_calls"] += 1
    ps = _find_powershell()
    with tempfile.TemporaryDirectory(prefix="certdiag_") as td:
        script = Path(td) / "collect.ps1"
        out = Path(td) / "out.json"
        script.write_text(PS_SCRIPT, encoding="utf-8-sig")
        cmd = [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", str(script), "-Path", path, "-Out", str(out), "-Revoke", revoke,
               "-Offline", ("true" if offline else "false")]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=timeout,
                                  **hidden_kwargs())
        except subprocess.TimeoutExpired:
            return {"path": path, "error": "采集超时（PowerShell 无响应）"}
        if not out.exists():
            return {"path": path,
                    "error": (proc.stderr or proc.stdout or "采集失败：未生成结果").strip()[:500]}
        return json.loads(out.read_text(encoding="utf-8"))


def collect(path: str | os.PathLike, timeout: float = 60,
            revoke: str = "NoCheck", offline: bool = False) -> dict:
    """采集单个文件；自动选择常驻 worker 或一次性 subprocess。"""
    global _worker, _use_worker
    p = str(Path(path))

    # 这两种是"输入不成立"，不是采集故障：直接给干净的结论，不用起 PowerShell，
    # 也不该触发 worker→一次性 的回退（回退只对传输层故障有意义）
    if not os.path.exists(p):
        return {"path": p, "error": "文件不存在", "error_kind": "not_found"}
    if os.path.isdir(p):
        return {"path": p, "error": "这是目录，请对单个文件诊断（或使用批量扫描）",
                "error_kind": "is_directory"}
    if _use_worker:
        try:
            with _worker_lock:
                if _worker is None:
                    _worker = PowerShellWorker()
                w = _worker
            _stats["worker_calls"] += 1
            res = w.collect(p, timeout=timeout, revoke=revoke, offline=offline)
            kind = res.get("error_kind")
            if res.get("error_kind") in ("not_found", "is_directory"):
                return res                      # 输入问题，回退没有意义
            if res.get("error") or not res.get("status"):
                # worker 重试完仍失败（内部故障/超时）才回退到一次性 subprocess
                _stats["worker_fallbacks"] += 1
                return _collect_subprocess(p, int(timeout), revoke, offline)
            return res
        except Exception:  # noqa: BLE001
            _stats["worker_fallbacks"] += 1
            _use_worker = False
    return _collect_subprocess(p, int(timeout), revoke, offline)


def stats() -> dict:
    return dict(_stats)


def close() -> None:
    """释放常驻进程；CLI 退出时调用。"""
    global _worker
    with _worker_lock:
        if _worker is not None:
            try:
                _worker.close()
            finally:
                _worker = None

"""psworker.py — 常驻 PowerShell 采集进程

问题：
    每诊断一个文件就启动一次 powershell.exe，冷启动约 1.0~1.5 秒。
    扫描一个有几百个 dll 的目录要十几分钟，完全不可用。

做法：
    启动一个常驻的 PowerShell 进程，通过 stdin/stdout 逐行收发 JSON：
        发送：{"path": "C:\\x\\y.dll"}
        接收：{"status": "...", ...}
    单次采集降到几十毫秒。

健壮性：
    - 任何异常都捕获成 {"error": ...}，不会让工作进程退出
    - 进程崩溃时自动重连一次；仍失败则调用方回退到单次模式
    - 关闭时发送空行并等待退出
"""
from __future__ import annotations

import json
import queue
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from queue import Queue, Empty


def hidden_kwargs() -> dict:
    """让子进程不弹出控制台窗口。

    从 pythonw（没有控制台）启动 powershell.exe 时，Windows 会给它新建一个
    可见的控制台窗口——用户会看到一个蓝色 PowerShell 窗口。
    用 CREATE_NO_WINDOW 抑制它。
    """
    if sys.platform.startswith("win"):
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)}
    return {}

from .ps_text import TS_FUNCTION

WORKER_PS_TEMPLATE = r"""
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

function Get-Sha256Safe {
  # Get-FileHash 在精简版 PowerShell 或受限模块路径下可能不存在。
  # SHA256 只是附加信息，不能因为它让整个诊断失败。
  param([string]$Path)
  try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '') }
    finally { $fs.Dispose(); $sha.Dispose() }
  } catch { }
  return $null
}

function Get-SigRecord {
  param([string]$Path, [string]$Revoke = 'NoCheck', [bool]$Offline = $false)

  $rec = [ordered]@{
    path = $Path; exists = $false; size = 0; sha256 = $null; error_kind = $null
    status = $null; status_message = $null
    signer = $null; signer_expired = $false; timestamper = $null
    chain = $null; crl_ocsp_urls = @(); error = $null
  }

  try {
    if (-not (Test-Path -LiteralPath $Path)) {
      $rec.error = "文件不存在"; $rec.error_kind = "not_found"; return $rec
    }
    if ((Get-Item -LiteralPath $Path) -is [System.IO.DirectoryInfo]) {
      $rec.error = "这是目录，请对单个文件诊断"; $rec.error_kind = "is_directory"; return $rec
    }
    $item = Get-Item -LiteralPath $Path
    $rec.path = $item.FullName
    $rec.exists = $true
    $rec.size = $item.Length
    $rec.sha256 = Get-Sha256Safe $item.FullName

    $sig = Get-AuthenticodeSignature -LiteralPath $item.FullName
    $rec.status = $sig.Status.ToString()
    $rec.status_message = $sig.StatusMessage

    $cert = $sig.SignerCertificate
    if ($cert) {
      $rec.signer = [ordered]@{
        subject = $cert.Subject; issuer = $cert.Issuer; thumbprint = $cert.Thumbprint
        serial = $cert.SerialNumber
        not_before = $cert.NotBefore.ToString('yyyy-MM-ddTHH:mm:ssK')
        not_after = $cert.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssK')
        version = $cert.Version
      }
      $rec.signer_expired = ($cert.NotAfter -lt (Get-Date))

      if ($sig.TimeStamperCertificate) {
        $ts = $sig.TimeStamperCertificate
        $rec.timestamper = [ordered]@{
          subject = $ts.Subject; thumbprint = $ts.Thumbprint
          not_after = $ts.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssK')
        }
      }

      $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
      $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::$Revoke
    # 离线模式：连中间证书（AIA）都不许下载，否则离线就是假的
    if ($Offline -and ($chain.ChainPolicy.PSObject.Properties.Name -contains 'DisableCertificateDownloads')) {
      $chain.ChainPolicy.DisableCertificateDownloads = $true
      $rec.aia_downloads_disabled = $true
    } else {
      $rec.aia_downloads_disabled = $false
    }
      $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
      $built = $chain.Build($cert)

      $elements = @(); $urls = New-Object System.Collections.ArrayList
      foreach ($el in $chain.ChainElements) {
        $st = @()
        foreach ($s in $el.ChainElementStatus) {
          $st += [ordered]@{ status = $s.Status.ToString(); info = $s.StatusInformation }
        }
        $elements += [ordered]@{
          subject = $el.Certificate.Subject; issuer = $el.Certificate.Issuer
          thumbprint = $el.Certificate.Thumbprint
          not_before = $el.Certificate.NotBefore.ToString('yyyy-MM-ddTHH:mm:ssK')
          not_after = $el.Certificate.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssK')
          status = $st
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
      $rec.chain = [ordered]@{ built = [bool]$built; elements = $elements; chain_status = $cs }
      $rec.crl_ocsp_urls = @($urls)
    }
  }
  catch {
    $rec.error = $_.Exception.Message
  }
  return $rec
}

while ($true) {
  __TS_FUNCTION__

$line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  if ($line.Trim() -eq '') { continue }
  $out = $null
  try {
    $job = $line | ConvertFrom-Json
    if ($job.op -eq 'timestamp') {
      try { $r = Get-TsRecord -Path $job.path }
      catch { $r = [ordered]@{ path = $job.path; error = $_.Exception.Message } }
      $r | ConvertTo-Json -Compress
      continue
    }
    $rev = if ($job.revoke) { $job.revoke } else { 'NoCheck' }
    $off = if ($job.offline) { $true } else { $false }
    $out = Get-SigRecord -Path $job.path -Revoke $rev -Offline $off
  }
  catch {
    $out = [ordered]@{ path = $job.path; error = $_.Exception.Message; error_kind = 'internal' }
  }
  $json = $out | ConvertTo-Json -Depth 10 -Compress
  [Console]::Out.WriteLine($json)
  [Console]::Out.Flush()
}
"""

WORKER_PS = WORKER_PS_TEMPLATE.replace("__TS_FUNCTION__", TS_FUNCTION)


def _find_powershell() -> str:
    from shutil import which
    # 优先 pwsh：从 PowerShell 7 的进程里启动 powershell.exe(5.1) 时，
    # 子进程会继承 PS7 的 PSModulePath，导致 5.1 加载不了自己的模块
    # （Get-AuthenticodeSignature 会报 module could not be loaded）。
    for name in ("pwsh.exe", "pwsh", "powershell.exe", "powershell"):
        p = which(name)
        if p:
            return p
    raise RuntimeError("未找到 PowerShell")


def _candidate_dirs() -> list[Path]:
    """按优先级给出可写目录候选。

    2026-11-22 实测：某些环境下便携版 Python 写 %LOCALAPPDATA% 会
    PermissionError，而 %TEMP% 里 mkstemp 会卡死（O_EXCL 创建被拦截）。
    因此不能硬编码一个目录，只能逐个探测；探测用普通 open('w')，
    失败是立刻抛异常，不会卡住。
    """
    env = os.environ.get("CERTDIAG_TMP")
    cands = []
    if env:
        cands.append(Path(env))
    cands += [
        Path.cwd() / ".certdiag-tmp",
        Path(tempfile.gettempdir()) / "certdiag-tmp",
        Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "certdiag" / "worker",
    ]
    return cands


def _worker_dir() -> Path:
    for d in _candidate_dirs():
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe = d / ".write-probe"
            with open(probe, "w", encoding="utf-8") as fh:
                fh.write("x")
            probe.unlink()
            return d
        except Exception:  # noqa: BLE001
            continue
    return Path(tempfile.gettempdir())


def _new_script_path(d: Path) -> str:
    """用普通 open('w') 建文件，避免 mkstemp 的 O_EXCL 在部分环境卡死。"""
    import uuid

    for _ in range(5):
        p = d / f"certdiag_worker_{uuid.uuid4().hex[:8]}.ps1"
        try:
            with open(p, "w", encoding="utf-8"):
                pass
            return str(p)
        except FileExistsError:
            continue
    raise RuntimeError(f"无法在 {d} 创建临时脚本")


def _cleanup_stale_scripts(max_age_hours: float = 24.0) -> None:
    """启动时清理一天前的残留脚本，避免越积越多。"""
    import time as _time

    cutoff = _time.time() - max_age_hours * 3600
    for d in _candidate_dirs():
        try:
            for f in d.glob("certdiag_worker_*.ps1"):
                try:
                    if f.stat().st_mtime < cutoff:
                        f.unlink()
                except OSError:
                    pass
        except OSError:
            pass


class PowerShellWorker:
    """一个进程内复用的采集器。用 with 语句或显式 close() 释放。"""

    def __init__(self, startup_timeout: float = 20.0):
        self._ps = _find_powershell()
        _cleanup_stale_scripts()
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self._start()

    # ---------- 生命周期 ----------
    def _start(self):
        # 脚本写到临时文件，再以 -File 启动；
        # 不能用 "-Command -"，那会把 stdin 整体当作脚本来读，无法逐行交互。
        self._script = _new_script_path(_worker_dir())
        with open(self._script, "w", encoding="utf-8-sig") as fh:
            fh.write(WORKER_PS)
        if getattr(self, "_script", None) and os.environ.get("CERTDIAG_KEEP_WORKER_SCRIPT"):
            print(f"[debug] worker 脚本保留在 {self._script}")
        self._proc = subprocess.Popen(
            [self._ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", self._script],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
            **hidden_kwargs())

    def close(self):
        if not self._proc:
            return
        try:
            self._proc.stdin.close()
            self._proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            self._proc.kill()
        finally:
            # 管道必须显式关闭，否则解释器退出时会报 unclosed file / subprocess still running
            for stream in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
                try:
                    if stream and not stream.closed:
                        stream.close()
                except Exception:  # noqa: BLE001
                    pass
            self._proc = None
            script = getattr(self, "_script", None)
            if script:
                try:
                    os.unlink(script)
                except OSError:
                    pass
                self._script = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---------- 采集 ----------
    def collect(self, path: str | Path, timeout: float = 30.0,
                revoke: str = "NoCheck", offline: bool = False) -> dict:
        path = str(Path(path))
        with self._lock:
            for attempt in (1, 2):
                try:
                    return self._request(path, timeout, revoke, offline)
                except Exception:  # noqa: BLE001
                    if attempt == 2:
                        return {"path": path, "error": "PowerShell 工作进程无响应"}
                    try:
                        self.close()
                    except Exception:  # noqa: BLE001
                        pass
                    self._start()
        return {"path": path, "error": "采集失败"}

    def timestamp(self, path: str | Path, timeout: float = 30.0) -> dict:
        """复用同一个 PowerShell 进程做时间戳解析。

        独立脚本每次要起进程 + 加载 System.Security（约 230 ms/文件）；
        常驻进程里只加载一次，单文件降到几毫秒。
        """
        path = str(Path(path))
        with self._lock:
            for attempt in (1, 2):
                try:
                    return self._request_op({"op": "timestamp", "path": path}, timeout)
                except Exception:  # noqa: BLE001
                    if attempt == 2:
                        raise
                    try:
                        self.close()
                    except Exception:  # noqa: BLE001
                        pass
                    self._start()
        raise RuntimeError("时间戳解析失败")

    def _request_op(self, payload: dict, timeout: float) -> dict:
        assert self._proc and self._proc.stdin and self._proc.stdout
        self._proc.stdin.write(json.dumps(payload, ensure_ascii=True) + "\n")
        self._proc.stdin.flush()
        q: queue.Queue = queue.Queue()

        def read():
            q.put(self._proc.stdout.readline())

        th = threading.Thread(target=read, daemon=True)
        th.start()
        try:
            line = q.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("采集超时") from None
        if not line:
            raise RuntimeError("worker 无输出")
        # 逻辑错误（文件没有嵌入签名等）是有效结论，原样返回；
        # 只有传输层失败（超时/进程死）才让调用方兜底
        return json.loads(line)

    def _request(self, path: str, timeout: float, revoke: str = "NoCheck",
                 offline: bool = False) -> dict:
        assert self._proc and self._proc.stdin and self._proc.stdout
        # ensure_ascii=True：把中文转成 \uXXXX 再传。
        # worker 的 stdin 按控制台代码页解码，直接写 UTF-8 中文会变成乱码，
        # 表现为"文件不存在"（实测：中文文件名必现）。
        payload = json.dumps({"path": path, "revoke": revoke, "offline": offline},
                                ensure_ascii=True)
        self._proc.stdin.write(payload + "\n")
        self._proc.stdin.flush()

        q: Queue = Queue()

        def reader():
            try:
                q.put(self._proc.stdout.readline())
            except Exception:  # noqa: BLE001
                q.put("")

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            line = q.get(timeout=timeout)
        except Empty:
            raise TimeoutError("采集超时")
        if not line:
            raise ConnectionError("工作进程已退出")
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            # 首行可能是脚本执行时的提示，丢弃后重试一次
            line2 = q.get(timeout=timeout) if not q.empty() else self._proc.stdout.readline()
            return json.loads(line2)


class WorkerPool:
    """多个 worker 并行，适合扫目录。默认 2 个（PowerShell 启动较重）。"""

    def __init__(self, size: int = 2):
        self.size = max(1, size)
        self._workers = [PowerShellWorker() for _ in range(self.size)]
        self._idx = 0
        self._lock = threading.Lock()

    def collect(self, path, timeout: float = 30.0) -> dict:
        with self._lock:
            self._idx = (self._idx + 1) % self.size
            w = self._workers[self._idx]
        return w.collect(path, timeout)

    def close(self):
        for w in self._workers:
            try:
                w.close()
            except Exception:  # noqa: BLE001
                pass

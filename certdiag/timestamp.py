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

from .psworker import hidden_kwargs, new_script_path, script_dir

from .ps_text import TS_SCRIPT as PS_SCRIPT  # 唯一来源：ps_text.py


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

    # 优先复用常驻 worker：省掉每次起进程 + 加载程序集（约 230 ms/文件）
    try:
        from .collect import timestamp_via_worker

        data = timestamp_via_worker(p, timeout=timeout)
        if isinstance(data, dict):
            result.update({k: v for k, v in data.items() if k != "path"})
            return result
    except Exception:  # noqa: BLE001
        pass  # 没有 worker 或失败 → 走下面的 一次性脚本

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

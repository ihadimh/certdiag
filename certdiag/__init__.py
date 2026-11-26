r"""certdiag — Windows 代码签名与证书链诊断工具（只读）。

两种用法：

    # 1) 库
    from certdiag import attribute
    report = attribute(r"C:\Windows\System32\cmd.exe", offline=True)
    report["diagnosis"]["category"]      # catalog_only_trust
    report["diagnosis"]["confidence"]    # high

    # 2) 命令行
    python -m certdiag <文件或目录> [--json 报告.json] [--sarif 报告.sarif]
"""
from __future__ import annotations

from pathlib import Path

__version__ = "2.4.0"

__all__ = ["attribute", "__version__"]


def attribute(path, *, offline: bool = False, no_probe: bool = False,
              timeout: float = 5.0, revoke: str = "cache",
              allow_private: bool = False, strict: bool = False,
              force_catalog: bool = False, force_timestamp: bool = False,
              revoke_timeout: float = 5.0, trace: bool = False) -> dict:
    """诊断单个文件，返回与 CLI ``--json`` 相同结构的报告字典。

    参数含义与命令行一致：

    - ``offline``：不发起任何网络请求（吊销状态会标为未检查）
    - ``no_probe``：不探测 CRL/OCSP 连通性
    - ``revoke``：off / cache / auto / online
    - ``allow_private``：允许探测内网地址（默认拒绝）
    - ``strict``：证据不足时降级为 unknown

    注意：默认 ``revoke="cache"`` 与 CLI 一致，可能启动 PowerShell 读取
    系统缓存；完全不想碰网络/子进程时传 ``offline=True``。

    返回的 dict 里至少包含 ``file`` / ``signature`` / ``diagnosis`` 三个键。
    """
    from .cli import diagnose_one

    return diagnose_one(
        Path(path),
        offline=offline,
        no_probe=no_probe,
        timeout=timeout,
        force_catalog=force_catalog,
        force_timestamp=force_timestamp,
        revoke_mode=revoke,
        allow_private=allow_private,
        strict=strict,
        trace=trace,
        revoke_timeout=revoke_timeout,
    )

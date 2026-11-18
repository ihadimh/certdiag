"""revoke.py — 吊销检查策略

背景：
    之前工具在**三处**都把吊销检查关掉了（链构建 NoCheck、WinVerifyTrust
    REVOKE_NONE、只做网络探测），却在结论里写"吊销检查通过"。
    这是把"没查"说成"查过了"。

现在把"要不要查"变成显式的选择，一共四档：

    off     不查（默认）。结论必须写"未检查"，不能写"通过"。
    cache   只用本地缓存（X509RevocationMode.Offline / CACHE_ONLY）。
            毫秒级；缓存没有就明确报未命中。
    auto    先探 CRL/OCSP 地址，可达才联网查，否则放弃并说明原因。
            ——探路不等于查证，但可以用探路来决定值不值得查证。
    online  强制联网查。慢（2~30 秒），且 WinVerifyTrust 没有超时参数。

设计要点：
    - 不为"快"牺牲诚实：off 档的结论就写"未检查"
    - auto 档复用 probe 的结果，把"网络探测"从推断依据降级为前置条件
"""
from __future__ import annotations

MODES = ("off", "cache", "auto", "online")

# 各档位对应的 .NET X509RevocationMode
DOTNET_MODE = {
    "off": "NoCheck",
    "cache": "Offline",
    "auto": "Online",
    "online": "Online",
}

DESCRIPTION = {
    "off": "不检查吊销状态",
    "cache": "只用本地缓存检查吊销",
    "auto": "地址可达时联网检查吊销",
    "online": "强制联网检查吊销",
}


class RevokePolicyError(ValueError):
    """参数组合不合法，例如 --offline 配 --revoke=online。"""


def normalize(mode: str | None) -> str:
    m = (mode or "off").strip().lower()
    if m not in MODES:
        raise RevokePolicyError(f"未知的吊销检查模式：{mode}（可选 {', '.join(MODES)}）")
    return m


def check_conflicts(mode: str, offline: bool) -> None:
    """离线模式与联网检查互斥。"""
    if offline and mode in ("auto", "online"):
        raise RevokePolicyError(
            f"--offline 与 --revoke={mode} 冲突：离线模式下无法联网查吊销")


def decide(mode: str, probes: list[dict]) -> tuple[str, str]:
    """根据探测结果决定实际执行哪一档。

    返回 (effective_mode, reason)。
      - auto + 所有吊销地址都不可达 → 退化为 off，并给出来由
      - 其他情况原样返回
    """
    if mode != "auto":
        return mode, ""

    targets = [p for p in probes if p.get("kind") in ("crl", "ocsp")]
    if not targets:
        return "off", "证书里没有可用的 CRL/OCSP 地址"

    reachable = [p for p in targets if p.get("category") == "ok"]
    if reachable:
        return "online", ""

    # 全都不通：不要白等 30 秒
    detail = targets[0].get("detail") or targets[0].get("category") or "未知原因"
    return "off", f"吊销地址不可达（{detail}）"


def summarize(mode: str, effective: str, checked: bool, revoked: bool,
              reason: str) -> dict:
    """归一化到报告里用的一份结构。"""
    if revoked:
        state = "revoked"
    elif checked:
        state = "checked_ok"
    elif reason:
        state = "unchecked"
    else:
        state = "unchecked"

    return {
        "mode": mode,                 # 用户要的档位
        "effective": effective,       # 实际执行的档位（auto 可能退化为 off）
        "checked": checked,           # 是否真的做了吊销检查
        "state": state,               # revoked / checked_ok / unchecked
        "reason": reason,             # 未检查或检查失败的原因
        "description": DESCRIPTION.get(mode, mode),
    }


def label(rev: dict) -> str:
    """给终端/报告用的一行说明。"""
    state = (rev or {}).get("state")
    if state == "revoked":
        return "吊销：已吊销"
    if state == "checked_ok":
        return "吊销：已检查（正常）"
    reason = (rev or {}).get("reason")
    mode = (rev or {}).get("mode", "off")
    if reason:
        return f"吊销：未检查（{reason}）"
    return f"吊销：未检查（--revoke={mode}）"

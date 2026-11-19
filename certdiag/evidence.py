"""evidence.py — 把"结论"变成"证据 + 冲突 + 未检查项"

为什么要有这一层：
    工具的判断全部来自系统 API。API 会给出互相矛盾的信号（状态 Valid、WinVerifyTrust 报错），
    也会因为环境限制给不出信号（没查吊销、PS 5.1 禁不掉 AIA）。
    这些情况如果只在文案里写一句"未校验"，用户没法据此做判断。

设计原则：
    1. 每条证据标出来源（谁说的）和分量（能支撑多强的结论）
    2. 冲突必须显式列出，不替用户选一个
    3. "没检查什么"是结构化字段，不是一句免责声明
    4. 置信度由证据推导，而不是规则里写死
"""
from __future__ import annotations

from dataclasses import dataclass, field

# 证据分量
HIGH = "high"        # 系统给出的、语义明确的结论（强错误码、哈希不匹配）
MEDIUM = "medium"    # 粗粒度状态、链状态、探测结果
LOW = "low"          # 间接推断
NONE = "none"        # 只是记录，不能支撑结论

# 一致性检查用的常量
_NO_SIGNATURE = 0x800B0100      # 目录签名场景下 WinVerifyTrust 的正常返回
_REVOCATION_UNKNOWN = {"offlinerevocation", "revocationstatusunknown", "revocationunknown"}


@dataclass
class Signal:
    source: str                 # powershell | winverifytrust | catalog | pe | timestamp | revocation
    name: str
    value: str
    weight: str = MEDIUM
    note: str = ""

    def to_dict(self) -> dict:
        return {"source": self.source, "name": self.name, "value": self.value,
                "weight": self.weight, "note": self.note}


def collect_signals(collected: dict, *, catalog: dict | None = None,
                    timestamp: dict | None = None,
                    revocation: dict | None = None) -> list[Signal]:
    """把采集结果摊成信号列表。只做描述，不做判断。"""
    out: list[Signal] = []
    status = collected.get("status") or ""
    hr = collected.get("hresult")

    out.append(Signal("powershell", "Authenticode 状态", status or "未知",
                      HIGH if status in ("Valid", "HashMismatch") else MEDIUM,
                      "Get-AuthenticodeSignature 的粗粒度状态，会回退查目录签名"))

    if hr is not None:
        name = collected.get("hresult_name") or "UNKNOWN"
        weak = hr not in (0, _NO_SIGNATURE)
        out.append(Signal("winverifytrust", "WinVerifyTrust",
                          f"0x{int(hr):08X} {name}",
                          HIGH if hr in (0x800B010C, 0x800B0111, 0x80096010) else MEDIUM,
                          "只看文件自身的嵌入式签名，不查目录签名"
                          + ("；与 PowerShell 状态不一致时以冲突处理" if weak else "")))

    pe = collected.get("pe") or {}
    if pe:
        if not pe.get("is_pe"):
            out.append(Signal("pe", "PE 结构", "不是有效 PE", MEDIUM,
                              pe.get("reason") or ""))
        elif pe.get("truncated"):
            out.append(Signal("pe", "PE 结构", "不完整（疑似截断）", MEDIUM,
                              pe.get("reason") or ""))
        else:
            trailing = int(pe.get("trailing_after_signature") or 0)
            note = f"证书表之后多出 {trailing} 字节" if trailing else ""
            out.append(Signal("pe", "PE 结构", "完整" + ("（有尾部数据）" if trailing else ""),
                              MEDIUM if trailing else LOW, note))

    cat = catalog or {}
    if cat.get("found"):
        st = cat.get("signature_status")
        out.append(Signal("catalog", "目录签名", str(st),
                          HIGH if st == "Valid" else MEDIUM,
                          f".cat 自身签名状态：{st}"))

    ts = timestamp or {}
    if ts:
        if not ts.get("has_signature"):
            out.append(Signal("timestamp", "时间戳", "无嵌入式签名", NONE, ""))
        elif ts.get("token_ok"):
            out.append(Signal("timestamp", "时间戳令牌", "验签通过", MEDIUM,
                              "只证明令牌未被篡改，未验证绑定与 TSA 链"))
        elif ts.get("has_token"):
            out.append(Signal("timestamp", "时间戳令牌", "验签失败", MEDIUM,
                              ts.get("error") or ""))
        else:
            out.append(Signal("timestamp", "时间戳", "存在标记但未解析", LOW, ""))

    rev = revocation or {}
    if rev:
        state = rev.get("state")
        weight = HIGH if state in ("checked_ok", "revoked") else NONE
        out.append(Signal("revocation", "吊销检查",
                          {"checked_ok": "已检查通过", "revoked": "已吊销",
                           "unchecked": "未检查"}.get(state, str(state)),
                          weight, rev.get("reason") or f"档位：{rev.get('mode')}"))

    aia = collected.get("aia_downloads_disabled")
    if aia is not None:
        out.append(Signal("offline", "AIA 下载",
                          "已禁止" if aia else "无法禁止",
                          LOW if aia else NONE,
                          "PS 5.1 / .NET Framework 4.8 不支持 DisableCertificateDownloads"
                          if not aia else ""))
    return out


def find_conflicts(signals: list[Signal], collected: dict) -> list[dict]:
    """列出互相矛盾的信号对，不做取舍。"""
    conflicts: list[dict] = []
    status = collected.get("status") or ""
    hr = collected.get("hresult")
    pe = collected.get("pe") or {}

    if status == "Valid" and hr is not None and hr not in (0, _NO_SIGNATURE):
        conflicts.append({
            "a": "powershell: Valid",
            "b": f"winverifytrust: 0x{int(hr):08X}",
            "reason": "系统状态说有效，WinVerifyTrust 却报错；可能是 API 侧限制，也可能是签名结构问题",
        })

    if status == "Valid" and pe and not pe.get("is_pe"):
        conflicts.append({
            "a": "powershell: Valid",
            "b": "pe: 不是有效 PE",
            "reason": "签名状态来自目录签名，但文件本身结构不完整——结论只对目录签名成立",
        })

    if status == "Valid" and pe.get("truncated"):
        conflicts.append({
            "a": "powershell: Valid",
            "b": "pe: 结构不完整",
            "reason": "证书表超出文件末尾，签名覆盖的数据可能已缺失",
        })
    return conflicts


def not_checked(collected: dict, *, timestamp: dict | None = None,
                revocation: dict | None = None,
                catalog: dict | None = None) -> list[str]:
    """明确列出"哪些项没有验证"。这是结论边界的一部分。"""
    out: list[str] = []
    rev = revocation or {}
    if rev.get("state") == "unchecked":
        out.append(f"吊销状态（{rev.get('reason') or '档位 ' + str(rev.get('mode'))}）")

    ts = timestamp or {}
    if not ts.get("has_signature"):
        out.append("时间戳（该文件无嵌入式签名）")
    elif not ts.get("token_ok"):
        out.append("时间戳令牌（未解析或验签失败）")
    else:
        out.append("时间戳绑定与 TSA 信任链（messageImprint / EKU / 链时效）")

    if (catalog or {}).get("found"):
        out.append("目录签名的独立复核（成员校验依赖 Windows 的结果）")
    else:
        out.append("目录签名（该文件未使用）")
    if collected.get("aia_downloads_disabled") is False:
        out.append("证书链 AIA 下载（当前运行时无法禁止）")
    if collected.get("status") is None:
        out.append("全部签名信息（采集失败）")
    return out


STRICT_CRITICAL_PREFIXES = ("吊销状态", "全部签名信息", "时间戳绑定")


def strict_critical(missing: list[str]) -> list[str]:
    """严格模式下会导致"无法判定"的缺口。

    只挑那些**直接支撑结论**的项：吊销、时间戳绑定、采集失败。
    目录签名的独立复核不在其中——Windows 的 Valid 状态本身已包含成员校验。
    """
    return [m for m in missing if m.startswith(STRICT_CRITICAL_PREFIXES)]


def adjust_confidence(base: str, conflicts: list[dict], missing: list[str]) -> tuple[str, str]:
    """置信度由证据推导：有冲突就降，有缺口最多到 medium。不升级。"""
    order = {"low": 0, "medium": 1, "high": 2}
    level = order.get(base, 1)

    if conflicts:
        return "low", "证据之间存在冲突，无法给出一致结论"

    # 吊销和时间戳是可选项，只有"关键信号缺失"才降级
    critical_missing = [m for m in missing if m.startswith("全部签名信息")]
    if critical_missing and level > order["medium"]:
        return "medium", f"存在未验证项：{critical_missing[0]}"
    return base, "所有可用信号一致"


def apply_strict(diag, missing: list[str]):
    """严格模式：证据不足就不下结论。invalid 是强证据，不受影响。

    返回 (是否降级, 原因列表)。
    """
    if getattr(diag, "verdict", "") == "invalid":
        return False, []
    critical = strict_critical(missing)
    if not critical:
        return False, []
    diag.verdict = "unknown"
    diag.cause = "证据不足，无法给确定结论：" + "；".join(critical)
    diag.confidence = "low"
    diag.confidence_basis = "严格模式：存在影响结论的未验证项"
    return True, critical

"""report.py — 报告渲染（JSON / Markdown / 终端摘要）"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from . import __version__
from .proxy import detect as detect_proxy
from pathlib import Path

VERDICT_LABEL = {
    "valid": "✅ 有效",
    "invalid": "❌ 无效",
    "unknown": "⚠️ 无法判定",
}

CATEGORY_LABEL = {
    "valid": "签名与证书链均正常",
    "valid_offline": "签名有效（离线，未查吊销）",
    "valid_revocation_checked_ok": "签名、链与吊销均已检查通过",
    "valid_revocation_unchecked": "签名有效，但未检查吊销",
    "revoked": "证书已被吊销",
    "not_applicable": "该文件类型没有签名概念",
    "expired_with_timestamp_signature_ok": "证书过期，时间戳令牌签名有效",
    "expired_with_broken_timestamp": "证书过期且时间戳无效",
    "no_signature": "无嵌入式签名",
    "catalog_signed": "由目录签名（catalog）覆盖",
    "wrong_usage": "证书用途不符（不能用于代码签名）",
    "malformed_signature": "签名结构不被系统接受",
    "unexplained_hresult": "系统状态与 WinVerifyTrust 结论矛盾",
    "not_pe_file": "内容不是有效的 PE 文件",
    "corrupt_pe": "PE 结构不完整（疑似截断）",
    "catalog_hash_mismatch": "目录签名自身无效（.cat 被改过）",
    "catalog_unverified": "由目录签名覆盖，但无法确认其有效性",
    "catalog_only_trust": "文件无嵌入签名，信任来自目录签名",
    "wrong_usage": "证书用途不符（不能用于代码签名）",
    "malformed_signature": "签名结构不被系统接受",
    "unexplained_hresult": "系统状态与 WinVerifyTrust 结论矛盾",
    "not_pe_file": "内容不是有效的 PE 文件",
    "corrupt_pe": "PE 结构不完整（疑似截断）",
    "catalog_hash_mismatch": "目录签名无效",
    "catalog_unverified": "目录签名无法验证",
    "hash_mismatch": "内容与签名不匹配",
    "revocation_unreachable": "吊销查询地址不可达（网络问题）",
    "revocation_not_checked": "离线模式，未查吊销",
    "revocation_unknown": "吊销状态未知",
    "revocation_unverified": "吊销状态未能验证（探测手段受限）",
    "untrusted_root": "根证书不受信任",
    "partial_chain": "证书链不完整",
    "expired": "证书已过期",
    "expired_with_timestamp": "证书过期但带时间戳",
    "key_usage": "证书用途不匹配",
    "unknown": "无法归因",
}


def _signals(collected: dict) -> dict:
    """把三个来源的原始结论摊开，并标出互相矛盾的情况。

    工具的结论建立在系统 API 之上；当 API 之间不一致时，用户有权看到原始值，
    而不是只看到我们挑出来的那一个。
    """
    status = collected.get("status") or ""
    hr = collected.get("hresult")
    try:
        hr_hex = f"0x{int(hr):08X}" if hr is not None else None
    except (TypeError, ValueError):
        hr_hex = None
    # 0x800B0100 = 没有嵌入式签名（目录签名场景的正常返回），0 = 通过
    conflict = bool(status == "Valid" and hr is not None and hr not in (0, 0x800B0100))
    return {
        "authenticode_status": status or None,
        "winverifytrust": hr_hex,
        "pe": {
            "is_pe": (collected.get("pe") or {}).get("is_pe"),
            "truncated": (collected.get("pe") or {}).get("truncated"),
            "trailing_after_signature": (collected.get("pe") or {}).get("trailing_after_signature"),
        },
        "aia_downloads_disabled": collected.get("aia_downloads_disabled"),
        "conflict": conflict,
    }


def build_report(collected: dict, probes: list[dict], diagnosis: dict, offline: bool,
                 catalog: dict | None = None, timestamp: dict | None = None) -> dict:
    return {
        "tool": "certdiag",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "offline": offline,
        "proxy": detect_proxy().to_dict(),
        "file": {
            "path": collected.get("path"),
            "size": collected.get("size"),
            "sha256": collected.get("sha256"),
        },
        "signature": {
            "status": collected.get("status"),
            "status_message": collected.get("status_message"),
            "hresult": collected.get("hresult"),
            "hresult_name": collected.get("hresult_name"),
            "hresult_desc": collected.get("hresult_desc"),
            "signer": collected.get("signer"),
            "signer_expired": collected.get("signer_expired"),
            "timestamper": collected.get("timestamper"),
        },
        "chain": collected.get("chain"),
        "catalog": catalog or {},
        "timestamp": timestamp or {},
        "signals": _signals(collected),
        "revocation_check": collected.get("revocation") or {},
        "revocation": {
            "urls": collected.get("crl_ocsp_urls") or [],
            "probes": probes,
        },
        "diagnosis": diagnosis,
        "collect_error": collected.get("error"),
    }


def _fmt_size(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n/1:.0f} {unit}"
        n /= 1024
    return f"{n} B"


def _cell(value) -> str:
    """表格单元格转义：竖线会截断 Markdown 表格，换行会破坏行结构。"""
    s = "" if value is None else str(value)
    return s.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def render_markdown(report: dict) -> str:
    d = report["diagnosis"]
    f = report["file"]
    sig = report["signature"]
    chain = report.get("chain") or {}
    lines: list[str] = []

    lines.append(f"# 证书诊断报告：{f.get('path')}")
    lines.append("")
    lines.append(f"- 生成时间：{report['generated_at']}")
    lines.append(f"- 模式：{'离线（未查询吊销）' if report['offline'] else '在线'}")
    lines.append(f"- 文件大小：{_fmt_size(f.get('size'))}")
    lines.append(f"- SHA256：`{f.get('sha256')}`")
    lines.append("")

    lines.append("## 一、结论")
    lines.append("")
    lines.append(f"**{VERDICT_LABEL.get(d['verdict'], d['verdict'])}** — {d['cause']}")
    lines.append("")
    lines.append(f"- 分类：`{d['category']}`（{CATEGORY_LABEL.get(d['category'], d['category'])}）")
    lines.append(f"- 置信度：{d['confidence']}")
    if d.get("advice"):
        lines.append("- 处置建议：")
        for a in d["advice"]:
            lines.append(f"  - {a}")
    if d.get("evidence"):
        lines.append("- 依据：")
        for e in d["evidence"]:
            lines.append(f"  - {e}")
    lines.append("")

    lines.append("## 二、签名信息")
    lines.append("")
    lines.append(f"- Authenticode 状态：`{sig.get('status')}`")
    if sig.get("hresult_name"):
        hr = sig.get("hresult") or 0
        lines.append(f"- WinVerifyTrust：`0x{hr:08X}` {sig.get('hresult_name')}（{sig.get('hresult_desc')}）")
    if sig.get("status_message"):
        lines.append(f"- 系统消息：{sig['status_message']}")
    signer = sig.get("signer")
    if signer:
        lines.append(f"- 签名者：{signer.get('subject')}")
        lines.append(f"- 颁发者：{signer.get('issuer')}")
        lines.append(f"- 有效期：{signer.get('not_before')} ~ {signer.get('not_after')}")
        if sig.get("signer_expired"):
            lines.append("- ⚠️ 签名者证书已过期")
    if sig.get("timestamper"):
        ts = sig["timestamper"]
        lines.append(f"- 时间戳：{ts.get('subject')}（到期 {ts.get('not_after')}）")
    else:
        lines.append("- 时间戳：无")
    lines.append("")

    lines.append("## 三、证书链")
    lines.append("")
    if chain and chain.get("elements"):
        lines.append(f"- 链构建成功：{'是' if chain.get('built') else '否'}")
        lines.append("")
        lines.append("| # | 主体 | 有效期至 | 状态 |")
        lines.append("|---|---|---|---|")
        for i, el in enumerate(chain["elements"], 1):
            flags = "、".join(s.get("status", "") for s in (el.get("status") or [])) or "正常"
            subject = (el.get("subject") or "")[:70]
            lines.append(f"| {i} | {_cell(subject)} | {(el.get('not_after') or '')[:10]} | {_cell(flags)} |")
        cs = chain.get("chain_status") or []
        if cs:
            lines.append("")
            lines.append("- 链级状态：" + "、".join(c.get("status", "") for c in cs))
    else:
        lines.append("- 无证书链信息（可能未签名或采集失败）")
    lines.append("")

    lines.append("## 四、目录签名（Catalog）")
    lines.append("")
    cat = report.get("catalog") or {}
    rc = report.get("revocation_check") or {}
    if rc:
        from .revoke import label as revoke_label
        out.append(revoke_label(rc))
    if cat.get("found"):
        lines.append(f"- 覆盖目录：`{cat.get('path')}`")
        lines.append(f"- 哈希算法：{cat.get('hash_alg')}   成员标记：`{(cat.get('member_tag') or '')[:32]}…`")
        lines.append(f"- 目录签名状态：`{cat.get('signature_status')}`")
        if cat.get("signer"):
            lines.append(f"- 目录签名者：{cat['signer']}")
        lines.append("")
        lines.append("> 系统文件常以目录签名形式发布：文件本身没有嵌入签名，"
                     "由 .cat 记录哈希并统一签名。此时\"文件未签名\"是正常形态。")
    else:
        lines.append("- 未找到覆盖该文件的目录签名。")
    lines.append("")

    rc = report.get("revocation_check") or {}
    if rc:
        from .revoke import label as revoke_label
        lines.append("## 四·五、吊销检查")
        lines.append("")
        lines.append(f"- 模式：`{rc.get('mode')}`（实际执行：`{rc.get('effective')}`）")
        lines.append(f"- 结论：{revoke_label(rc)}")
        if rc.get("reason"):
            lines.append(f"- 原因：{rc['reason']}")
        lines.append("")

    lines.append("## 五、吊销查询（CRL / OCSP）")
    lines.append("")
    urls = (report.get("revocation") or {}).get("urls") or []
    probes = (report.get("revocation") or {}).get("probes") or []
    if report["offline"]:
        lines.append("- 以离线模式运行，未发起网络请求。")
    elif not urls:
        lines.append("- 证书中未找到 CRL/OCSP 地址。")
    else:
        lines.append(f"- 共发现 {len(urls)} 个地址：")
        lines.append("")
        lines.append("| URL | DNS | TCP | HTTP | 判定 | 说明 |")
        lines.append("|---|---|---|---|---|---|")
        for p in probes:
            lines.append(
                f"| {_cell(p.get('url'))} | {_cell(p.get('dns'))} | {_cell(p.get('tcp'))} | {_cell(p.get('http') or '-')} "
                f"| {_cell(p.get('category'))} | {_cell((p.get('detail') or '')[:40])} |")
    lines.append("")

    if report.get("collect_error"):
        lines.append("## 采集异常")
        lines.append("")
        lines.append(f"```\n{report['collect_error']}\n```")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("> 本工具只做只读诊断，不修改系统信任库，也不用于绕过签名验证。")
    return "\n".join(lines)


def render_console(report: dict) -> str:
    d = report["diagnosis"]
    f = report["file"]
    sig = report["signature"]
    probes = (report.get("revocation") or {}).get("probes") or []
    cat = report.get("catalog") or {}
    ok = sum(1 for p in probes if p.get("category") == "ok")
    inc = sum(1 for p in probes if p.get("category") == "inconclusive")
    ocsp_bad = sum(1 for p in probes
                   if p.get("kind") == "ocsp" and p.get("category") not in ("ok", "inconclusive"))
    out = [
        f"文件：{f.get('path')}",
        f"状态：{sig.get('status')}" + (f"（{sig['status_message']}）" if sig.get("status_message") else ""),
        f"结论：{VERDICT_LABEL.get(d['verdict'], d['verdict'])} — {d['cause']}",
        f"分类：{d['category']}  置信度：{d['confidence']}",
    ]
    rc = report.get("revocation_check") or {}
    if rc:
        from .revoke import label as revoke_label
        out.append(revoke_label(rc))
    if cat.get("found"):
        cat_name = (cat.get("path") or "").split("\\")[-1]
        out.append(f"目录签名：{cat_name}（{cat.get('signature_status')}）")
    if probes:
        tail = ""
        if inc:
            tail = f"，{inc} 个 OCSP 端点无法用 GET 判定（正常）"
        elif ok < len(probes):
            tail = f"，{len(probes) - ok} 个地址不可达（见报告）"
        out.append(f"吊销查询：{ok}/{len(probes)} 个地址可达" + tail)
    if d.get("advice"):
        out.append("建议：" + "；".join(d["advice"][:2]))
    return "\n".join(out)


def dump_json(report: dict, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

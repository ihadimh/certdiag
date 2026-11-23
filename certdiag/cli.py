"""cli.py — 命令行入口

用法：
    python -m certdiag <文件或目录> [更多路径...]
        [--json 报告.json] [--md 报告.md]
        [--offline] [--no-probe] [--catalog] [--timeout 5]
"""
from __future__ import annotations

import argparse
from datetime import datetime
import sys
from pathlib import Path

from .attrib import diagnose_from_collect
from .catalog import find_catalog
from .collect import close as close_worker, collect
from .probe import probe_all
from .report import build_report, dump_json, render_console, render_markdown
from . import revoke as revoke_policy
from . import evidence as evidence_layer
from .pe import inspect as pe_inspect, looks_like_pe_name
from .timestamp import verify as timestamp_verify
from .winverify import verify as wv_verify

PE_EXT = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".msi", ".ps1", ".cab"}


def _expand(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file() and f.suffix.lower() in PE_EXT:
                    out.append(f)
        elif path.exists():
            out.append(path)
        else:
            print(f"[跳过] 路径不存在：{p}", file=sys.stderr)
    return out


def _catalog_info(path: Path) -> dict:
    """查找覆盖该文件的 .cat，并验证 .cat 自身的签名。"""
    cat = find_catalog(path)
    if not cat.get("catalog_path"):
        return {"found": False, "path": None, "error": cat.get("error")}
    cat_sig = collect(cat["catalog_path"])
    signer = (cat_sig.get("signer") or {}).get("subject")
    return {
        "found": True,
        "path": cat["catalog_path"],
        "member_tag": cat.get("member_tag"),
        "hash_alg": cat.get("hash_alg"),
        "signature_status": cat_sig.get("status"),
        "signature_message": cat_sig.get("status_message"),
        "signer": signer,
        "signature_error": cat_sig.get("error"),
    }


def _trace_on(enabled: bool):
    """返回一个打印函数；默认写 stderr，避免污染 stdout 的报告内容。"""
    if not enabled:
        return lambda *a, **k: None

    def emit(msg: str) -> None:
        print(f"[trace] {msg}", file=sys.stderr, flush=True)

    return emit


def diagnose_one(path: Path, offline: bool, no_probe: bool, timeout: float,
                 force_catalog: bool = False, force_timestamp: bool = False,
                 revoke_mode: str = "off", allow_private: bool = False,
                 strict: bool = False, trace: bool = False) -> dict:
    emit = _trace_on(trace)
    emit(f"输入：{path}")

    collected = collect(path, offline=offline)
    emit(f"采集：status={collected.get('status')} "
         f"error={collected.get('error')} "
         f"证书过期={bool(collected.get('signer_expired'))} "
         f"链元素={len(((collected.get('chain') or {}).get('elements') or []))} "
         f"CRL/OCSP地址={len(collected.get('crl_ocsp_urls') or [])}")

    # 结构探测：只在扩展名像程序时做，用来区分"文件损坏"和"类型不支持"
    pe_info: dict = {}
    if looks_like_pe_name(str(path)):
        pe_info = pe_inspect(str(path))
        collected["pe"] = pe_info

    # WinVerifyTrust 只看文件自身的嵌入式签名，能给出精确 HRESULT
    wv = wv_verify(str(path), offline=offline)
    collected["hresult"] = wv.get("hresult")
    collected["hresult_name"] = wv.get("name")
    collected["hresult_desc"] = wv.get("desc")

    emit(f"WinVerifyTrust：0x{(wv.get('hresult') or 0):08X} {wv.get('name')}")
    if pe_info:
        emit(f"PE 结构：is_pe={pe_info.get('is_pe')} truncated={pe_info.get('truncated')}")

    # 时间戳只在"证书已过期"时才有判断价值（决定过期是否影响签名有效性），
    # 默认不跑，避免批量扫描每个文件多花约 250ms
    ts: dict = {}
    if force_timestamp or collected.get("signer_expired"):
        ts = timestamp_verify(str(path))
        collected["timestamp"] = ts

    if ts:
        emit(f"时间戳：has_token={ts.get('has_token')} token_ok={ts.get('token_ok')} "
             f"error={ts.get('error')}")

    catalog: dict = {}
    if (force_catalog
            or collected.get("status") in ("NotSigned", "NotSupportedFileFormat")
            or collected.get("hresult") == 0x800B0100):
        catalog = _catalog_info(path)

    emit(f"目录签名：found={catalog.get('found')} path={catalog.get('path')}")

    probes: list[dict] = []
    if not offline and not no_probe:
        urls = collected.get("crl_ocsp_urls") or []
        probes = [p.to_dict() for p in probe_all(urls, timeout=timeout,
                                                  allow_private=allow_private)]

    # 决定实际执行哪一档吊销检查（auto 可能因地址不可达退化为 off）
    effective, reason = revoke_policy.decide(revoke_mode, probes)
    if effective != "off" and collected.get("status"):
        dotnet_mode = revoke_policy.DOTNET_MODE[effective]
        checked_collected: dict = {}
        try:
            checked_collected = collect(path, revoke=dotnet_mode, offline=offline)
        except Exception as e:  # noqa: BLE001
            checked_collected = {"path": str(path), "error": f"吊销复查异常：{e}"}

        if checked_collected.get("error") or not checked_collected.get("status"):
            # 复查没拿到有效结果：不能沿用"已检查"的结论，退回未检查并写明原因
            reason = str(checked_collected.get("error") or "吊销复查未返回有效状态")
            effective = "off"
        else:
            collected = checked_collected
            collected["hresult"] = wv.get("hresult")
            collected["hresult_name"] = wv.get("name")
            collected["hresult_desc"] = wv.get("desc")
            wv = wv_verify(str(path), offline=offline, revoke=effective)

    chain_status = (collected.get("chain") or {}).get("chain_status") or []
    statuses = {(x.get("status") or "").lower() for x in chain_status}

    revoked = bool(wv.get("hresult") == 0x800B010C) or "revoked" in statuses

    # checked 不能只看"档位不是 off"：链可能报告吊销状态无法确认（缓存未命中、
    # 地址不可达）。那种情况必须算"没查成"，否则结论和末行会自相矛盾。
    rev_unknown_flags = {"offlinerevocation", "revocationstatusunknown", "revocationunknown"}
    rev_undetermined = bool(statuses & rev_unknown_flags)
    # 还需要"确实有链元素"：采集失败/空链时状态集为空，不能因此得出"检查过"
    chain_elements = (collected.get("chain") or {}).get("elements") or []
    checked = effective != "off" and not rev_undetermined and bool(chain_elements)
    if effective != "off" and rev_undetermined and not reason:
        reason = "系统链报告 OfflineRevocation"

    revocation = revoke_policy.summarize(revoke_mode, effective,
                                         checked=checked,
                                         revoked=revoked, reason=reason)
    collected["revocation"] = revocation

    emit(f"吊销档位：请求={revoke_mode} 实际={effective} 已检查={checked} "
         f"已吊销={revoked} 原因={reason}")

    diag = diagnose_from_collect(collected, probes, offline=offline,
                                 catalog=catalog, timestamp=ts,
                                 revocation=revocation, pe=pe_info)

    emit(f"归因：{diag.category} → {diag.verdict}（{diag.confidence}）原因={diag.cause}")

    # 证据层：把信号摊开、找冲突、列出未检查项，并据此重算置信度
    signals = evidence_layer.collect_signals(
        collected, catalog=catalog, timestamp=ts, revocation=revocation)
    conflicts = evidence_layer.find_conflicts(signals, collected, diag.category)
    missing = evidence_layer.not_checked(collected, timestamp=ts,
                                       revocation=revocation, catalog=catalog)
    confidence, basis = evidence_layer.adjust_confidence(diag.confidence, conflicts, missing)
    diag.confidence = confidence
    diag.confidence_basis = basis
    diag.signals = [s.to_dict() for s in signals]
    diag.conflicts = conflicts
    diag.not_checked = missing

    emit(f"证据：信号 {len(signals)} 条，冲突 {len(conflicts)} 条，未验证 {len(missing)} 项")
    emit(f"置信度：{diag.confidence}（{diag.confidence_basis}）")
    if strict:
        emit(f"严格模式：{diag.verdict} / {diag.confidence}")

    # 严格模式：证据不足就不下结论（invalid 是强证据，不受影响）
    if strict:
        evidence_layer.apply_strict(diag, missing)
    return build_report(collected, probes, diag.to_dict(), offline,
                        catalog=catalog, timestamp=ts)


def fix_console() -> None:
    """让控制台输出不会因为编码问题崩溃。

    中文 Windows 的控制台默认是 GBK，遇到 ✅/❌ 这类字符会抛
    UnicodeEncodeError 直接把程序打挂。这里做两件事：
      1. 任何情况下都把 errors 设为 replace（保底不崩）
      2. 如果当前编码不是 UTF-8，切成 UTF-8（配合 chcp 65001 显示正常）
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:  # noqa: BLE001
            pass
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    if enc and enc.replace("-", "") != "utf8":
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass


EXIT_OK = 0        # 全部有效
EXIT_INVALID = 1   # 存在无效
EXIT_UNKNOWN = 2   # 没有无效，但存在无法判定（仅在 --fail-on unknown 时）
EXIT_ERROR = 3     # 跑不起来：路径不存在 / 没有可处理文件 / 采集失败


def count_verdicts(reports: list[dict]) -> dict[str, int]:
    counts = {"valid": 0, "invalid": 0, "unknown": 0}
    for rep in reports:
        v = (rep.get("diagnosis") or {}).get("verdict") or "unknown"
        counts[v] = counts.get(v, 0) + 1
    return counts


def exit_code(reports: list[dict], fail_on: str = "invalid") -> int:
    """把诊断结果映射成退出码，供脚本和 CI 直接消费。

    fail_on=invalid（默认）：有无效才失败，无法判定只警告
    fail_on=unknown      ：无法判定也算失败（更严格）
    fail_on=none         ：永远返回 0，只看报告
    """
    if not reports:
        return EXIT_ERROR
    counts = count_verdicts(reports)
    if counts.get("invalid"):
        return EXIT_INVALID if fail_on != "none" else EXIT_OK
    if fail_on == "unknown" and counts.get("unknown"):
        return EXIT_UNKNOWN
    return EXIT_OK


def filter_reports(reports: list[dict], only: str) -> list[dict]:
    if only == "all":
        return reports
    return [r for r in reports
            if ((r.get("diagnosis") or {}).get("verdict") or "unknown") == only]


SIGNATURE_MISSING = {"no_signature", "not_applicable", "catalog_unverified"}


def without_signature(reports: list[dict]) -> list[dict]:
    """返回"拿不出可验证签名"的报告（用于 --require-signature 门禁）。"""
    out = []
    for r in reports:
        d = r.get("diagnosis") or {}
        if d.get("category") in SIGNATURE_MISSING:
            out.append(r)
    return out


def main(argv: list[str] | None = None) -> int:
    fix_console()
    ap = argparse.ArgumentParser(
        prog="certdiag",
        description="Windows 代码签名与证书链诊断工具（只读）",
        epilog="退出码：0=全部有效  1=存在无效  2=存在无法判定（--fail-on unknown）  3=运行错误")
    ap.add_argument("paths", nargs="*", help="要诊断的 exe/dll/sys 文件或目录")
    ap.add_argument("--json", metavar="FILE", help="把结构化报告写到 JSON")
    ap.add_argument("--md", metavar="FILE", help="把可读报告写到 Markdown")
    ap.add_argument("--offline", action="store_true", help="离线模式：不发起任何网络请求")
    ap.add_argument("--no-probe", action="store_true", help="不探测 CRL/OCSP 连通性")
    ap.add_argument("--catalog", action="store_true",
                    help="强制检查目录签名（catalog），即使文件已有嵌入式签名")
    ap.add_argument("--timeout", type=float, default=5.0, help="单个网络探测超时秒数（默认 5）")
    ap.add_argument("--timestamp", action="store_true",
                    help="强制验证时间戳令牌（默认只在签名者证书过期时验证）")
    ap.add_argument("--allow-private", action="store_true",
                    help="允许探测内网/回环地址（证书里的地址不可信，默认拒绝）")
    ap.add_argument("--strict", action="store_true",
                    help="保守模式：任何影响结论的证据缺口（如未查吊销）都判为「无法判定」")
    ap.add_argument("--trace", action="store_true",
                    help="打印决策过程（采集→归因→证据→置信度），用于理解或排错")
    ap.add_argument("--require-signature", action="store_true",
                    help="把「无签名 / 无法验证签名」也视为失败（退出码 1），用于签名门禁")
    ap.add_argument("--revoke", choices=list(revoke_policy.MODES),
                    default=revoke_policy.DEFAULT,
                    help="吊销检查档位：cache（默认，只读本地缓存）/ off（不查）/ "
                         "auto（探测可达才联网查）/ online（强制联网）")
    ap.add_argument("-q", "--quiet", action="store_true", help="批量模式下只输出汇总")
    ap.add_argument("--only", choices=["all", "invalid", "unknown", "valid"], default="all",
                    help="只输出指定结论的报告（默认 all）")
    ap.add_argument("--fail-on", choices=["invalid", "unknown", "none"], default="invalid",
                    help="什么情况算失败：invalid（默认）/ unknown（更严格）/ none")
    ap.add_argument("--ui", action="store_true", help="启动本地图形界面（浏览器打开）")
    ap.add_argument("--port", type=int, default=8765, help="界面端口（默认 8765）")
    ap.add_argument("--no-browser", action="store_true", help="启动界面时不自动打开浏览器")
    args = ap.parse_args(argv)

    try:
        args.revoke = revoke_policy.normalize(args.revoke)
        revoke_policy.check_conflicts(args.revoke, args.offline)
    except revoke_policy.RevokePolicyError as e:
        print(f"参数错误：{e}", file=sys.stderr)
        return EXIT_ERROR

    if args.no_probe and args.revoke in ("auto", "online"):
        print("[提示] --no-probe 与 --revoke=" + args.revoke +
              " 冲突：auto 依赖探测结果判断可达性，没有探测会退化为「不查」。"
              " 需要联网查解除 --no-probe。", file=sys.stderr)

    if args.ui:
        from .ui import serve
        # 拖到快捷方式上时，文件会作为位置参数传进来：直接在界面里诊断它
        initial = str(args.paths[0]) if args.paths else None
        serve(port=args.port, open_browser=not args.no_browser, initial_path=initial)
        return 0

    if not args.paths:
        ap.print_help()
        print("\n提示：想用图形界面请加 --ui", file=sys.stderr)
        return EXIT_ERROR

    files = _expand(args.paths)
    if not files:
        print("没有可处理的文件。", file=sys.stderr)
        return EXIT_ERROR

    reports = []
    failed: list[str] = []
    try:
        for f in files:
            try:
                rep = diagnose_one(f, args.offline, args.no_probe, args.timeout,
                                   args.catalog, args.timestamp, args.revoke,
                                   args.allow_private, args.strict,
                                   trace=args.trace)
            except Exception as e:  # noqa: BLE001
                failed.append(str(f))
                print(f"[!] 诊断失败：{f} — {e}", file=sys.stderr)
                continue
            reports.append(rep)
            if not args.quiet:
                print("-" * 70)
                print(render_console(rep))
    finally:
        close_worker()

    shown = filter_reports(reports, args.only)
    counts = count_verdicts(reports)

    # 多文件，或使用了筛选/只看汇总时，给一行统计
    if len(files) > 1 or args.only != "all":
        print("=" * 70)
        print(f"共 {len(reports)} 个文件："
              f"有效 {counts.get('valid', 0)}  "
              f"无效 {counts.get('invalid', 0)}  "
              f"无法判定 {counts.get('unknown', 0)}")
        if args.only != "all":
            print(f"按 --only {args.only} 筛选后输出 {len(shown)} 个")
        for rep in shown:
            v = rep["diagnosis"]["verdict"]
            mark = {"valid": "✅", "invalid": "❌", "unknown": "⚠️"}.get(v, "·")
            print(f"  {mark} {rep['file']['path']}  [{rep['diagnosis']['category']}]")

    if args.json:
        # 结构固定成对象：单文件和多文件都返回 {"schema_version", "reports": [...]}。
        # 以前"1 条输出对象、多条输出数组"，做 --only 过滤后类型会变，脚本会炸。
        from . import __version__ as _ver
        dump_json({
            "schema_version": 2,
            "tool": "certdiag",
            "tool_version": _ver,
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "count": len(shown),
            "reports": shown,
        }, args.json)
        print(f"\nJSON 报告已写入：{args.json}（{len(shown)} 条）")
    if args.md:
        text = "\n\n".join(render_markdown(r) for r in shown)
        Path(args.md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.md).write_text(text, encoding="utf-8")
        print(f"Markdown 报告已写入：{args.md}（{len(shown)} 条）")

    if failed:
        print(f"\n {len(failed)} 个文件诊断失败（工具自身出错，不是文件的问题）", file=sys.stderr)
        return EXIT_ERROR

    if args.require_signature and args.fail_on == "invalid":
        print("[提示] 门禁场景建议同时加 --fail-on unknown --strict："
              "默认配置下「无法判定」不会让退出码变 1。", file=sys.stderr)

    code = exit_code(reports, args.fail_on)
    if args.require_signature and without_signature(reports):
        print("\n --require-signature：存在没有可验证签名的文件，按失败处理", file=sys.stderr)
        code = EXIT_INVALID
    return code


if __name__ == "__main__":
    raise SystemExit(main())

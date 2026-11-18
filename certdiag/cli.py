"""cli.py — 命令行入口

用法：
    python -m certdiag <文件或目录> [更多路径...]
        [--json 报告.json] [--md 报告.md]
        [--offline] [--no-probe] [--catalog] [--timeout 5]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .attrib import diagnose_from_collect
from .catalog import find_catalog
from .collect import close as close_worker, collect
from .probe import probe_all
from .report import build_report, dump_json, render_console, render_markdown
from . import revoke as revoke_policy
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


def diagnose_one(path: Path, offline: bool, no_probe: bool, timeout: float,
                 force_catalog: bool = False, force_timestamp: bool = False,
                 revoke_mode: str = "off") -> dict:
    collected = collect(path)

    # WinVerifyTrust 只看文件自身的嵌入式签名，能给出精确 HRESULT
    wv = wv_verify(str(path), offline=offline)
    collected["hresult"] = wv.get("hresult")
    collected["hresult_name"] = wv.get("name")
    collected["hresult_desc"] = wv.get("desc")

    # 时间戳只在"证书已过期"时才有判断价值（决定过期是否影响签名有效性），
    # 默认不跑，避免批量扫描每个文件多花约 250ms
    ts: dict = {}
    if force_timestamp or collected.get("signer_expired"):
        ts = timestamp_verify(str(path))
        collected["timestamp"] = ts

    catalog: dict = {}
    if (force_catalog
            or collected.get("status") in ("NotSigned", "NotSupportedFileFormat")
            or collected.get("hresult") == 0x800B0100):
        catalog = _catalog_info(path)

    probes: list[dict] = []
    if not offline and not no_probe:
        urls = collected.get("crl_ocsp_urls") or []
        probes = [p.to_dict() for p in probe_all(urls, timeout=timeout)]

    # 决定实际执行哪一档吊销检查（auto 可能因地址不可达退化为 off）
    effective, reason = revoke_policy.decide(revoke_mode, probes)
    if effective != "off" and collected.get("status"):
        dotnet_mode = revoke_policy.DOTNET_MODE[effective]
        collected = collect(path, revoke=dotnet_mode)
        collected["hresult"] = wv.get("hresult")
        collected["hresult_name"] = wv.get("name")
        collected["hresult_desc"] = wv.get("desc")
        wv = wv_verify(str(path), offline=offline, revoke=effective)

    revoked = bool(wv.get("hresult") == 0x800B010C) or any(
        (x.get("status") or "").lower() == "revoked"
        for x in ((collected.get("chain") or {}).get("chain_status") or []))
    revocation = revoke_policy.summarize(revoke_mode, effective,
                                         checked=effective != "off",
                                         revoked=revoked, reason=reason)
    collected["revocation"] = revocation

    diag = diagnose_from_collect(collected, probes, offline=offline,
                                 catalog=catalog, timestamp=ts,
                                 revocation=revocation)
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
    ap.add_argument("--revoke", choices=list(revoke_policy.MODES), default="off",
                    help="吊销检查档位：off（默认，不查）/ cache（只用缓存）/ "
                         "auto（地址可达才查）/ online（强制联网）")
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
    try:
        for f in files:
            rep = diagnose_one(f, args.offline, args.no_probe, args.timeout,
                               args.catalog, args.timestamp, args.revoke)
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
        out = shown[0] if len(shown) == 1 else shown
        dump_json(out, args.json)
        print(f"\nJSON 报告已写入：{args.json}（{len(shown)} 条）")
    if args.md:
        text = "\n\n".join(render_markdown(r) for r in shown)
        Path(args.md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.md).write_text(text, encoding="utf-8")
        print(f"Markdown 报告已写入：{args.md}（{len(shown)} 条）")

    return exit_code(reports, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())

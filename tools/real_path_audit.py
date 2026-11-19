# -*- coding: utf-8 -*-
"""真实路径审计：逐条跑采集入口，记录耗时、关键字段与异常。

不是单元测试——这里每一条都会真的起 PowerShell / 调 WinVerifyTrust / 发网络请求。
输出 JSON 到 docs/audit-<日期>.json，便于和上一次对比。

用法：
    python tools/real_path_audit.py            # 全跑
    python tools/real_path_audit.py --fast     # 跳过联网与 online 吊销
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from certdiag import collect as collect_mod
from certdiag import timestamp as ts_mod
from certdiag.catalog import find_catalog
from certdiag.probe import probe_url
from certdiag.revoke import decide, summarize
from certdiag.winverify import verify as wv_verify

ROOT = Path(__file__).resolve().parent.parent
CMD = Path(r"C:\Windows\System32\cmd.exe")
SAMPLES = ROOT / "samples"
RESULTS: list[dict] = []


def record(name: str, fn, keys=(), expect=None):
    t0 = time.perf_counter()
    entry = {"name": name}
    try:
        out = fn()
        entry["ms"] = round((time.perf_counter() - t0) * 1000)
        if hasattr(out, "to_dict"):      # ProbeResult 之类
            out = out.to_dict()
        if isinstance(out, dict):
            entry["keys_present"] = all(k in out for k in keys) if keys else None
            entry["summary"] = {k: out.get(k) for k in keys if k in out}
            if out.get("error_kind"):
                entry["error_kind"] = out["error_kind"]
            if out.get("error"):
                entry["error"] = str(out["error"])[:160]
        else:
            entry["result"] = repr(out)[:160]
        entry["ok"] = True
    except Exception as e:  # noqa: BLE001
        entry["ms"] = round((time.perf_counter() - t0) * 1000)
        entry["ok"] = False
        entry["exception"] = f"{type(e).__name__}: {e}"
        entry["trace"] = traceback.format_exc(limit=2)[-400:]
    RESULTS.append(entry)
    flag = "OK " if entry["ok"] else "EXC"
    print(f"[{flag}] {name:34s} {entry['ms']:>6} ms  {entry.get('error','')}")
    return entry


def main(fast: bool) -> int:
    print("=" * 78)
    print("真实路径审计（每一条都走真实入口）")
    print("=" * 78)

    # ---------- 采集层 ----------
    r = record("collect.worker", lambda: collect_mod.collect(str(CMD)),
               ("status", "sha256", "signer"))
    record("collect.worker.offline", lambda: collect_mod.collect(str(CMD), offline=True),
           ("status", "aia_downloads_disabled"))
    record("collect.oneshot", lambda: collect_mod._collect_subprocess(str(CMD), 60, "NoCheck", "false"),
           ("status", "sha256"))
    record("collect.oneshot.offline", lambda: collect_mod._collect_subprocess(str(CMD), 60, "NoCheck", "true"),
           ("status", "aia_downloads_disabled"))
    record("collect.revoke.cache", lambda: collect_mod.collect(str(CMD), revoke="Offline"),
           ("status", "chain"))
    if not fast:
        record("collect.revoke.online", lambda: collect_mod.collect(str(CMD), revoke="Online"),
               ("status", "chain"))
    record("collect.missing", lambda: collect_mod.collect(r"Z:\definitely\not\here.exe"),
           ("error",))
    record("collect.directory", lambda: collect_mod.collect(str(ROOT / "samples")), ("error",))

    # ---------- 签名 ----------
    record("winverify.system-file", lambda: wv_verify(str(CMD), revoke="off"),
           ("hresult", "name"))
    tampered = SAMPLES / "tampered.exe"
    if tampered.exists():
        record("winverify.tampered", lambda: wv_verify(str(tampered)),
               ("hresult", "name"))
    record("winverify.cache-mode", lambda: wv_verify(str(CMD), revoke="cache"),
           ("hresult", "name"))
    record("winverify.missing", lambda: wv_verify(r"Z:\nope.exe"), ("hresult", "error"))

    # ---------- 目录签名 ----------
    record("catalog.system-file", lambda: find_catalog(str(CMD)), ("found", "catalog_path"))
    tmp_unsigned = Path(os.environ["TEMP"]) / "audit_unsigned.bin"
    tmp_unsigned.write_bytes(b"not signed\n")
    record("catalog.unsigned", lambda: find_catalog(str(tmp_unsigned)), ("found",))
    record("catalog.missing", lambda: find_catalog(r"Z:\nope.exe"), ("error",))

    # ---------- 时间戳 ----------
    signed = SAMPLES / "signed_ok.exe"
    if signed.exists():
        record("timestamp.signed", lambda: ts_mod.verify(str(signed)),
               ("has_signature", "token_ok", "tsa_subject"))
        trunc = Path(os.environ["TEMP"]) / "audit_trunc.exe"
        trunc.write_bytes(signed.read_bytes()[:8192])
        record("timestamp.truncated", lambda: ts_mod.verify(str(trunc)), ("error", "has_signature"))
    record("timestamp.system-file", lambda: ts_mod.verify(str(CMD)), ("has_signature",))
    record("timestamp.missing", lambda: ts_mod.verify(r"Z:\nope.exe"), ("error",))
    empty = Path(os.environ["TEMP"]) / "audit_empty.exe"
    empty.write_bytes(b"")
    record("timestamp.empty", lambda: ts_mod.verify(str(empty)), ("error",))

    # ---------- 探测 ----------
    record("probe.private", lambda: probe_url("http://127.0.0.1:9/x.crl"),
           ("category", "detail"))
    if not fast:
        record("probe.public", lambda: probe_url("http://crl3.digicert.com/x.crl"),
               ("category",))
        record("probe.ocsp", lambda: probe_url("http://ocsp.digicert.com"),
               ("category",))
    record("probe.bad-url", lambda: probe_url("ht!tp://%%%"), ("category",))
    record("probe.nxdomain", lambda: probe_url("http://no-such-host.invalid/x.crl", timeout=4),
           ("category",))

    # ---------- 端到端 ----------
    from certdiag.cli import diagnose_one

    record("diagnose.offline", lambda: diagnose_one(CMD, offline=True, no_probe=True, timeout=5.0),
           ("diagnosis", "signals"))
    if tampered.exists():
        record("diagnose.tampered", lambda: diagnose_one(tampered, offline=True, no_probe=True, timeout=5.0),
               ("diagnosis",))

    # ---------- 边界输入 ----------
    tmpdir = Path(os.environ["TEMP"]) / "audit_edge"
    tmpdir.mkdir(exist_ok=True)
    cases = {
        "edge.zero": tmpdir / "zero.exe",
        "edge.nonpe": tmpdir / "text.dll",
        "edge.spaces": tmpdir / "a b c.exe",
        "edge.brackets": tmpdir / "x[1].dll",
        "edge.unicode": tmpdir / "中文 文件.exe",
    }
    for name, path in cases.items():
        path.write_bytes(b"hello")
        record(name, (lambda p: (lambda: diagnose_one(p, offline=True, no_probe=True, timeout=5.0)))(path),
               ("diagnosis",))

    # 被独占锁定的文件
    locked = tmpdir / "locked.exe"
    locked.write_bytes(b"MZ")
    handle = open(locked, "r+b")
    try:
        record("edge.locked", lambda: diagnose_one(locked, offline=True, no_probe=True, timeout=5.0),
               ("diagnosis",))
    finally:
        handle.close()

    # ---------- worker 崩溃恢复 ----------
    def kill_and_recollect():
        collect_mod._use_worker = True
        first = collect_mod.collect(str(CMD))
        pid = getattr(getattr(collect_mod._worker, "_proc", None), "pid", None)
        if pid:
            os.system(f"taskkill /PID {pid} /F >NUL 2>&1")
            time.sleep(0.8)
        second = collect_mod.collect(str(CMD))
        return {"status": second.get("status"), "stats": collect_mod.stats(),
                "_first": first.get("status")}

    record("worker.killed-then-recover", kill_and_recollect, ("status", "stats"))

    # ---------- 汇总 ----------
    out = ROOT / "docs" / f"audit-{time.strftime('%Y%m%d-%H%M')}.json"
    out.write_text(json.dumps(RESULTS, ensure_ascii=False, indent=2), encoding="utf-8")
    bad = [r for r in RESULTS if not r.get("ok")]
    odd = [r for r in RESULTS if r.get("ok") and r.get("error")]
    print("-" * 78)
    print(f"共 {len(RESULTS)} 项：异常 {len(bad)}，返回错误 {len(odd)}")
    for r in bad:
        print(f"  [EXC] {r['name']}: {r.get('exception')}")
    for r in odd:
        print(f"  [ERR] {r['name']}: {r['error']}")
    print(f"明细：{out}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main("--fast" in sys.argv))

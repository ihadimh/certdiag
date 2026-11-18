"""demo.py — 一次跑完所有典型场景，用来直观对比诊断结果

用法：
    python tools/demo.py

输出一张表：场景 / 结论 / 分类 / 一句话依据
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
try:
    from certdiag.cli import fix_console
    fix_console()
except Exception:
    pass

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from certdiag.cli import close_worker, diagnose_one  # noqa: E402

MARK = {"valid": "✅", "invalid": "❌", "unknown": "⚠️"}


def find_unsigned() -> Path | None:
    """找一个确实没有签名的可执行文件，用于演示 no_signature。"""
    import subprocess
    roots = [Path.home() / "Desktop", Path.home() / "Downloads"]
    for root in roots:
        if not root.is_dir():
            continue
        for f in root.glob("*.exe"):
            try:
                out = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"(Get-AuthenticodeSignature -LiteralPath '{f}').Status"],
                    capture_output=True, text=True, timeout=20)
                if "NotSigned" in out.stdout:
                    return f
            except Exception:  # noqa: BLE001
                continue
    return None


def main() -> int:
    cases: list[tuple[str, Path, dict]] = []

    cmd = Path(r"C:\Windows\System32\cmd.exe")
    if cmd.exists():
        cases.append(("系统组件（仅目录签名）", cmd, {"no_probe": True}))

    samples = ROOT / "samples"
    if not (samples / "tampered.exe").exists():
        import subprocess
        subprocess.run([sys.executable, str(samples / "make_samples.py")], check=False)
    if (samples / "signed_ok.exe").exists():
        cases.append(("原始副本（证书过期 + 时间戳）", samples / "signed_ok.exe",
                      {"no_probe": True}))
    if (samples / "tampered.exe").exists():
        cases.append(("被改过一个字节", samples / "tampered.exe", {"no_probe": True}))

    pt = Path(r"C:\Program Files\Cisco Packet Tracer 9.0.1\bin\PacketTracer.exe")
    if pt.exists():
        cases.append(("离线模式（不查吊销）", pt, {"offline": True}))

    unsigned = find_unsigned()
    if unsigned:
        cases.append(("从未签名（桌面/下载）", unsigned, {"no_probe": True}))

    print(f"\n共 {len(cases)} 个场景\n" + "=" * 96)
    print(f"{'场景':<26}{'结论':<10}{'分类':<30}{'一句话依据'}")
    print("-" * 96)

    rows = []
    for label, path, opts in cases:
        try:
            rep = diagnose_one(path, offline=opts.get("offline", False),
                               no_probe=opts.get("no_probe", False),
                               timeout=5.0, force_catalog=False)
        except Exception as e:  # noqa: BLE001
            rows.append((label, "错误", str(e)[:28], ""))
            continue
        d = rep["diagnosis"]
        icon = MARK.get(d["verdict"], "?")
        rows.append((label, f"{icon} {d['verdict']}", d["category"], d["cause"]))

    close_worker()

    for label, verdict, cat, cause in rows:
        short = cause.replace("\n", " ")[:44]
        print(f"{label:<26}{verdict:<12}{cat:<32}{short}")
    print("=" * 96)
    print("\n判据：unknown ≠ invalid；NotSigned ≠ 被篡改；过期 + 时间戳 ≠ 失效。\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""verify.py — 一键自检

跑三件事：
    1. 单元测试（归因引擎的各条规则）
    2. 三个真实场景（目录签名 / 正常签名 / 篡改样本）
    3. 汇总成一张"体检报告"

用途：
    拿到代码的人可以先跑这个，确认环境和判断都正常，再去看界面。
    退出码 0 表示全部通过。
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from certdiag.cli import fix_console  # noqa: E402

fix_console()   # 英文版 Windows 的控制台是 cp1252，不先修中文会直接崩

OK, BAD, WARN = "[OK]", "[!!]", "[--]"


def run_tests() -> tuple[bool, str]:
    print("=" * 68)
    print("1/2  单元测试")
    print("=" * 68)
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    tail = (proc.stderr or proc.stdout).strip().splitlines()
    for line in tail[-4:]:
        print("    " + line)
    return proc.returncode == 0, "\n".join(tail[-4:])


def ensure_samples() -> Path | None:
    d = ROOT / "samples"
    if not (d / "make_test_samples.py").exists():
        return None
    tampered = d / "tampered.exe"
    if not tampered.exists():
        subprocess.run([sys.executable, str(d / "make_test_samples.py")],
                       cwd=ROOT, check=False)
    return tampered


def scenario(name: str, path: Path, expect_categories: tuple[str, ...],
             expect_verdict: str, no_probe: bool = True) -> bool:
    from certdiag.cli import diagnose_one, close_worker

    t0 = time.time()
    try:
        rep = diagnose_one(path, offline=False, no_probe=no_probe,
                           timeout=5.0, force_catalog=True)
    except Exception as e:  # noqa: BLE001
        print(f"    {BAD} {name}：调用失败 — {e}")
        return False
    finally:
        close_worker()

    d = rep.get("diagnosis") or {}
    cat, verdict = d.get("category", ""), d.get("verdict", "")
    ok = verdict == expect_verdict and cat in expect_categories
    ms = (time.time() - t0) * 1000
    mark = OK if ok else BAD
    print(f"    {mark} {name}")
    print(f"        文件：{path.name}")
    print(f"        结论：{verdict}（{cat}） 耗时 {ms:.0f} ms")
    print(f"        说明：{d.get('cause', '')[:64]}")
    if not ok:
        print(f"        期望：{expect_verdict}（{'/'.join(expect_categories)}）")
        # 诊断：为什么没拿到状态？把采集层的错误原样打出来
        try:
            from certdiag.collect import close as _close, collect as _collect

            raw = _collect(path)
            print(f"        采集键：{sorted(raw.keys())}")
            if raw.get("error"):
                print(f"        采集错误：{str(raw['error'])[:300]}")
            print(f"        采集状态：{raw.get('status')!r}")
            _close()
        except Exception as exc:  # noqa: BLE001
            print(f"        采集异常：{type(exc).__name__}: {exc}")
    return ok


def env_info() -> dict:
    """收集环境信息，用于 `--report` 生成可粘贴的自检报告。"""
    import importlib.util
    import platform

    info = {
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "python": f"{platform.python_version()}  ({sys.executable})",
        "powershell": "未找到",
        "ps_version": "-",
        "cmdlet_auth": "未知",
        "cmdlet_hash": "未知",
        "proxy": "未知",
        "cryptography": "未安装",
    }

    try:
        from certdiag.proxy import detect

        info["proxy"] = detect().describe()
    except Exception:  # noqa: BLE001
        pass

    if importlib.util.find_spec("cryptography"):
        info["cryptography"] = "已安装"

    try:
        from certdiag.psworker import _find_powershell

        ps = _find_powershell()
        info["powershell"] = ps
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$a = (Get-Command Get-AuthenticodeSignature) -ne $null;"
            "$h = (Get-Command Get-FileHash) -ne $null;"
            "Write-Output ($PSVersionTable.PSVersion.ToString() + '|' + $a + '|' + $h)"
        )
        proc = subprocess.run([ps, "-NoProfile", "-Command", script],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=30)
        parts = (proc.stdout or "").strip().split("|")
        if len(parts) == 3:
            info["ps_version"] = parts[0]
            info["cmdlet_auth"] = "可用" if parts[1].strip().lower() == "true" else "缺失"
            info["cmdlet_hash"] = "可用" if parts[2].strip().lower() == "true" else "缺失"
    except Exception as e:  # noqa: BLE001
        info["powershell"] = f"探测失败：{e}"

    return info


def write_report(path: Path, env: dict, results: list[tuple[str, bool]]) -> None:
    from datetime import datetime

    lines = [
        "# certdiag 环境自检报告",
        "",
        f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 版本：{__import__('certdiag').__version__}",
        "",
        "## 环境",
        "",
        "| 项 | 值 |",
        "|---|---|",
        f"| 操作系统 | {env['os']} |",
        f"| Python | {env['python']} |",
        f"| PowerShell | {env['powershell']} |",
        f"| PS 版本 | {env['ps_version']} |",
        f"| Get-AuthenticodeSignature | {env['cmdlet_auth']} |",
        f"| Get-FileHash | {env['cmdlet_hash']} |",
        f"| 代理 | {env['proxy']} |",
        f"| cryptography（可选） | {env['cryptography']} |",
        "",
        "## 自检结果",
        "",
        "| 项目 | 结果 |",
        "|---|---|",
    ]
    for name, ok in results:
        lines.append(f"| {name} | {'✅ 通过' if ok else '❌ 失败'} |")
    lines += ["", f"**总计：{sum(1 for _, ok in results if ok)}/{len(results)} 通过**", ""]

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n环境报告已写入：{path}")


def main() -> int:
    # 先生成样本：单元测试里有依赖 samples/ 的用例，新机器上否则会 skip
    try:
        ensure_samples()
    except Exception:  # noqa: BLE001
        pass

    report_path = None
    argv = sys.argv[1:]
    if "--report" in argv:
        i = argv.index("--report")
        if i + 1 < len(argv):
            report_path = Path(argv[i + 1])

    print("\ncertdiag 自检\n")
    results = []

    tests_ok, _ = run_tests()
    results.append(("单元测试", tests_ok))

    print()
    print("=" * 68)
    print("2/2  真实场景")
    print("=" * 68)

    # 场景 1：系统组件，只有目录签名
    cmd = Path(r"C:\Windows\System32\cmd.exe")
    if cmd.exists():
        results.append(("目录签名组件",
                        scenario("系统组件（仅目录签名）", cmd,
                                 ("catalog_only_trust", "no_signature"), "valid")))

    # 场景 2：篡改样本必须判为无效
    tampered = ensure_samples()
    if tampered is None:
        print("    [--] 跳过：便携包未包含 samples/（样本需在完整仓库里生成）")
        return True
    if tampered.exists():
        results.append(("篡改检测",
                        scenario("篡改样本（必须判无效）", tampered,
                                 ("hresult:TRUST_E_BAD_DIGEST", "hash_mismatch"), "invalid")))

    # 场景 3：未篡改的副本应为有效
    ok_file = ROOT / "samples" / "signed_ok.exe"
    if ok_file.exists():
        results.append(("原始副本",
                        scenario("原始副本（应为有效）", ok_file,
                                 ("valid", "expired_with_timestamp",
                                  "expired_with_timestamp_signature_ok",
                                  "catalog_only_trust"), "valid")))

    print()
    print("=" * 68)
    print("体检报告")
    print("=" * 68)
    all_ok = True
    for name, ok in results:
        print(f"    {OK if ok else BAD}  {name}")
        all_ok &= ok
    print()
    if all_ok:
        print("    全部通过 —— 现在可以启动界面：双击启动脚本，或运行 --ui")
    else:
        print("    有项目未通过，请查看上面的输出。")

    if report_path:
        write_report(report_path, env_info(), results)

    print()
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

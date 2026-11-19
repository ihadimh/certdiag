# -*- coding: utf-8 -*-
"""build_corpus.py — 生成本机签名测试语料

为什么用"生成"而不是"分发"：
    1. System32 里的二进制是微软的版权文件，打包分发不合适
    2. 篡改/截断样本最容易被杀软误报，不该随包传播
    3. 语料要匹配被测机器（不同 Windows 版本的系统组件不同）

所以做法是：在目标机器上跑这个脚本，从它自己的 System32 复制并按类别挑选，
同时生成边界样本。产物只留在本机。

用法：
    python tools/build_corpus.py                     # 默认 120 个文件
    python tools/build_corpus.py --limit 60 --out D:\\corpus
    python tools/build_corpus.py --no-generate       # 只复制系统文件
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from certdiag.cli import diagnose_one  # noqa: E402


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def pick(candidates: list[Path], limit: int) -> list[dict]:
    """按分类做均衡挑选，而不是取前 N 个。"""
    buckets: dict[str, list[dict]] = {}
    for f in candidates:
        try:
            rep = diagnose_one(f, offline=True, no_probe=True, timeout=5.0)
        except Exception:  # noqa: BLE001
            continue
        d = rep.get("diagnosis") or {}
        cat = d.get("category") or "unknown"
        bucket = (cat.split(":")[0] if cat.startswith("hresult:") else cat)
        buckets.setdefault(bucket, []).append({
            "file": f, "category": cat,
            "verdict": d.get("verdict"), "confidence": d.get("confidence"),
        })

    # 每类先取 1/3，再按需补齐，避免某一类占满
    # 每类最多占 40%，其余分给稀缺类别
    per_bucket = max(4, min(limit // 3, int(limit * 0.4)))
    chosen: list[dict] = []
    for bucket, items in sorted(buckets.items()):
        chosen.extend(items[:per_bucket])
    if len(chosen) < limit:
        rest = [i for items in buckets.values() for i in items if i not in chosen]
        chosen.extend(rest[: limit - len(chosen)])
    return chosen[:limit]


def generate_edges(out: Path, signed: Path | None) -> list[dict]:
    """生成边界样本：篡改、截断、0 字节、非 PE、特殊文件名。"""
    made: list[dict] = []
    edge = out / "edge-cases"
    edge.mkdir(parents=True, exist_ok=True)

    if signed and signed.exists():
        data = signed.read_bytes()
        tampered = bytearray(data)
        # 改签名数据区末尾一个字节：内容与摘要不符，但文件仍可解析
        tampered[0x400] ^= 0xFF if len(tampered) > 0x400 else 0
        (edge / "tampered.exe").write_bytes(bytes(tampered))
        made.append({"file": "edge-cases/tampered.exe", "kind": "篡改（改末尾字节）"})

        (edge / "truncated.exe").write_bytes(data[:8192])
        made.append({"file": "edge-cases/truncated.exe", "kind": "截断的 PE（8KB）"})

        (edge / "中文 文件.exe").write_bytes(data[:65536])
        made.append({"file": "edge-cases/中文 文件.exe", "kind": "中文文件名"})

        (edge / "a b c.exe").write_bytes(data[:65536])
        made.append({"file": "edge-cases/a b c.exe", "kind": "空格文件名"})

        (edge / "x[1].dll").write_bytes(data[:65536])
        made.append({"file": "edge-cases/x[1].dll", "kind": "通配符字符文件名"})

    (edge / "zero.exe").write_bytes(b"")
    made.append({"file": "edge-cases/zero.exe", "kind": "0 字节"})

    (edge / "not-a-pe.dll").write_bytes(b"this is not a PE file\n")
    made.append({"file": "edge-cases/not-a-pe.dll", "kind": "非 PE 内容"})

    return made



def strip_signature(src: Path, dst: Path) -> bool:
    """把 PE 安全目录清零，得到"无签名"样本（结构仍完整）。"""
    import struct

    data = bytearray(src.read_bytes())
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return False
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    dd = pe + 24 + (112 if magic == 0x20B else 96) + 4 * 8
    struct.pack_into("<II", data, dd, 0, 0)   # 清空 security directory
    # 再翻转末尾一个字节：System32 的文件都在系统目录库里，
    # 不改内容的话去掉嵌入签名后仍会被目录签名覆盖（判成 catalog_only_trust）
    data[-1] ^= 0xFF
    dst.write_bytes(bytes(data))
    return True


def make_synthetic(out: Path, base: Path | None) -> list[dict]:
    """用自签名证书造 untrusted_root 样本；用清空安全目录造 no_signature 样本。"""
    made: list[dict] = []
    if not base or not base.exists():
        return made
    syn = out / "synthetic"
    syn.mkdir(parents=True, exist_ok=True)

    unsigned = syn / "unsigned.exe"
    if strip_signature(base, unsigned):
        made.append({"file": "synthetic/unsigned.exe", "kind": "去掉安全目录（无签名）"})

    selfsigned = syn / "selfsigned.exe"
    shutil.copy2(base, selfsigned)
    ps = (
        "$ErrorActionPreference='Stop';"
        "$c = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=certdiag synthetic' "
        "-CertStoreLocation Cert:\\CurrentUser\\My -NotAfter (Get-Date).AddYears(1);"
        f"Set-AuthenticodeSignature -FilePath '{selfsigned}' -Certificate $c | Out-Null;"
        "Remove-Item (\"Cert:\\CurrentUser\\My\\$($c.Thumbprint)\") -Force"
    )
    try:
        import subprocess

        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-Command", ps], capture_output=True, timeout=120)
        if selfsigned.exists() and selfsigned.stat().st_size > 0:
            made.append({"file": "synthetic/selfsigned.exe", "kind": "自签名（根不受信）"})
    except Exception:  # noqa: BLE001
        pass
    return made


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=120)
    ap.add_argument("--out", default=str(ROOT / "corpus"))
    ap.add_argument("--no-generate", action="store_true")
    args = ap.parse_args()

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    win = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    pools = {
        "System32/dll": sorted((win / "System32").glob("*.dll")),
        "System32/exe": sorted((win / "System32").glob("*.exe")),
        "drivers/sys": sorted((win / "System32" / "drivers").glob("*.sys")),
        "SysWOW64/dll": sorted((win / "SysWOW64").glob("*.dll"))[:200],
    }
    # 每个池都取一些，避免全是同一种来源
    candidates: list[Path] = []
    for name, files in pools.items():
        files = [f for f in files if f.is_file()]
        take = max(20, args.limit // len(pools))
        candidates.extend(files[:take])
        print(f"  {name:16s} 取 {min(take, len(files))} / {len(files)}")
    print(f"候选合计：{len(candidates)}")

    chosen = pick(candidates, args.limit)
    print(f"按分类挑选：{len(chosen)} 个")

    manifest: list[dict] = []
    for item in chosen:
        src: Path = item["file"]
        bucket = item["category"].split(":")[0]
        dst_dir = out / "signed" / bucket
        dst_dir.mkdir(parents=True, exist_ok=True)
        dst = dst_dir / src.name
        shutil.copy2(src, dst)
        manifest.append({
            "file": str(dst.relative_to(out)).replace("\\", "/"),
            "sha256": sha256(dst),
            "size": dst.stat().st_size,
            "expected_category": item["category"],
            "expected_verdict": item["verdict"],
            "source": "System32",
        })

    # 基底优先选"有嵌入式签名"的文件（hresult==0），这样篡改后才会得到 HashMismatch
    signed_sample = None
    for item in chosen:
        try:
            from certdiag.winverify import verify as _wv
            if (_wv(str(item["file"])).get("hresult") or -1) == 0:
                signed_sample = item["file"]
                break
        except Exception:  # noqa: BLE001
            continue
    if signed_sample is None:
        signed_sample = next((o["file"] for o in chosen if o["verdict"] == "valid"), None)
    if signed_sample is None:
        signed_sample = next((o["file"] for o in chosen), None)
    if not args.no_generate:
        for extra in make_synthetic(out, Path(signed_sample) if signed_sample else None):
            p2 = out / extra["file"]
            cat = ver = None
            try:
                rep2 = diagnose_one(p2, offline=True, no_probe=True, timeout=5.0)
                d2 = rep2.get("diagnosis") or {}
                cat, ver = d2.get("category"), d2.get("verdict")
            except Exception:  # noqa: BLE001
                pass
            manifest.append({
                "file": extra["file"].replace("\\", "/"),
                "sha256": sha256(p2), "size": p2.stat().st_size,
                "expected_category": cat, "expected_verdict": ver,
                "source": "synthetic", "kind": extra["kind"],
            })
        for extra in generate_edges(out, Path(signed_sample) if signed_sample else None):
            p = out / extra["file"]
            manifest.append({
                "file": extra["file"].replace("\\", "/"),
                "sha256": sha256(p),
                "size": p.stat().st_size,
                "expected_category": None,
                "expected_verdict": None,
                "source": "generated",
                "kind": extra["kind"],
            })

    (out / "manifest.json").write_text(
        json.dumps({"generated_by": "tools/build_corpus.py", "count": len(manifest),
                    "items": manifest}, ensure_ascii=False, indent=2),
        encoding="utf-8")

    (out / "README.md").write_text(
        "# 签名测试语料\n\n"
        "由 `tools/build_corpus.py` 在本机生成，**不要提交到仓库、不要分发**：\n\n"
        "- `signed/<分类>/` —— 从本机 System32 复制的系统组件，按诊断分类归档\n"
        "- `edge-cases/` —— 生成的边界样本（篡改、截断、0 字节、非 PE、特殊文件名）\n"
        "- `manifest.json` —— 每个文件的哈希、预期分类与 verdict\n\n"
        "## 用法\n\n"
        "```powershell\n"
        "python -m certdiag corpus\\signed --no-probe -q\n"
        "python -m certdiag corpus\\edge-cases --no-probe\n"
        "```\n\n"
        "## 安全提示\n\n"
        "`edge-cases/` 里是**故意做坏的文件**，杀软可能误报。只在测试环境保留。\n",
        encoding="utf-8")

    want = {"catalog_only_trust", "expired_with_timestamp_signature_ok",
            "expired_with_timestamp", "no_signature", "valid_offline",
            "partial_chain", "untrusted_root", "corrupt_pe", "not_pe_file"}
    have = {i["expected_category"] for i in manifest if i["expected_category"]}
    have = {h.split(":")[0] for h in have}
    print("覆盖缺口：", sorted(want - have) or "无")

    total = sum(i["size"] for i in manifest)
    print(f"完成：{len(manifest)} 个文件，{total / 1024 / 1024:.1f} MB -> {out}")
    print("分类分布：")
    dist: dict[str, int] = {}
    for i in manifest:
        k = i["expected_category"] or "edge-case"
        dist[k] = dist.get(k, 0) + 1
    for k, v in sorted(dist.items(), key=lambda x: -x[1]):
        print(f"  {k:38s} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

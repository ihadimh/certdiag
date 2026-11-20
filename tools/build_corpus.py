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
# 控制台编码保护：英文 Windows 的 stdout 是 cp1252，print 中文会直接抛
# UnicodeEncodeError。这里只保证"不崩"，显示效果交给 chcp。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001
        pass

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
    """生成边界样本：篡改、截断、0 字节、非 PE、特殊文件名。

    篡改样本优先复用 samples/tampered.exe（已确认会得到 HashMismatch）；
    其余样本与它无关，无论复不复用都要生成。
    """
    made: list[dict] = []
    edge = out / "edge-cases"
    edge.mkdir(parents=True, exist_ok=True)

    data = signed.read_bytes() if signed and signed.exists() else None

    _known = ROOT / "samples" / "tampered.exe"
    if _known.exists():
        shutil.copy2(_known, edge / "tampered.exe")
        made.append({"file": "edge-cases/tampered.exe", "kind": "篡改（复用 samples/tampered.exe）"})
    elif data:
        tampered = bytearray(data)
        try:
            import struct as _st
            _pe = _st.unpack_from("<I", tampered, 0x3C)[0]
            _coff = _pe + 4
            _n = _st.unpack_from("<H", tampered, _coff + 2)[0]
            _osz = _st.unpack_from("<H", tampered, _coff + 16)[0]
            _sec = _coff + 20 + _osz
            for _i in range(_n):
                _b = _sec + _i * 40
                _name = bytes(tampered[_b:_b + 8]).rstrip(b"\0")
                _rs = _st.unpack_from("<I", tampered, _b + 16)[0]
                _rp = _st.unpack_from("<I", tampered, _b + 20)[0]
                if _name == b".text" and _rs > 64:
                    tampered[_rp + _rs // 2] ^= 0xFF
                    break
        except Exception:  # noqa: BLE001
            pass
        (edge / "tampered.exe").write_bytes(bytes(tampered))
        made.append({"file": "edge-cases/tampered.exe", "kind": "篡改（改 .text 段）"})

    if data and len(data) > 8192:
        (edge / "truncated.exe").write_bytes(data[:8192])
        made.append({"file": "edge-cases/truncated.exe", "kind": "截断的 PE（8KB）"})

        # 文件名测试要用**完整文件**：截断的副本会被判成 corrupt_pe，测不到文件名处理
        for name, kind in (("中文 文件.exe", "中文文件名"),
                           ("a b c.exe", "空格文件名"),
                           ("x[1].dll", "通配符字符文件名")):
            (edge / name).write_bytes(data)
            made.append({"file": f"edge-cases/{name}", "kind": kind})

    (edge / "zero.exe").write_bytes(b"")
    made.append({"file": "edge-cases/zero.exe", "kind": "0 字节"})

    (edge / "not-a-pe.dll").write_bytes(b"this is not a PE file\n")
    made.append({"file": "edge-cases/not-a-pe.dll", "kind": "非 PE 内容"})

    return made



def strip_signature(src: Path, dst: Path) -> bool:
    """把 PE 安全目录清零，再改一个字节：得到"无签名且不被目录覆盖"的样本。"""
    import struct

    data = bytearray(src.read_bytes())
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return False
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    dd = pe + 24 + (112 if magic == 0x20B else 96) + 4 * 8
    struct.pack_into("<II", data, dd, 0, 0)
    data[-1] ^= 0xFF
    dst.write_bytes(bytes(data))
    return True


def make_synthetic(out: Path, base: Path | None) -> list[dict]:
    """自签名（untrusted_root）与去签名（no_signature）样本。"""
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
        if selfsigned.exists():
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
    out.mkdir(parents=True, exist_ok=True)

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
    _pre = ROOT / "samples" / "signed_ok.exe"
    if _pre.exists():
        try:
            from certdiag.winverify import verify as _wv0
            if (_wv0(str(_pre)).get("hresult") or -1) == 0:
                signed_sample = _pre
        except Exception:  # noqa: BLE001
            pass
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
    if signed_sample is not None:
        print(f"样本基底：{signed_sample}")
        if (ROOT / "samples" / "signed_ok.exe").exists() and Path(signed_sample) != (ROOT / "samples" / "signed_ok.exe"):
            print("  （samples/signed_ok.exe 在本次环境中不是 S_OK，已回退到系统文件；"
                  "副本会体现该文件本身的签名形态）")
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

    # 兜底：任何还没有预期分类的条目（边界/合成样本），补跑一次诊断填上
    for item in manifest:
        if item.get("expected_category"):
            continue
        try:
            rep = diagnose_one(out / item["file"], offline=True, no_probe=True, timeout=5.0)
            d = rep.get("diagnosis") or {}
            item["expected_category"] = d.get("category")
            item["expected_verdict"] = d.get("verdict")
        except Exception:  # noqa: BLE001
            pass

    (out / "manifest.json").write_text(
        json.dumps({"generated_by": "tools/build_corpus.py",
                    "base_sample": str(signed_sample) if signed_sample else None,
                    "count": len(manifest), "items": manifest},
                   ensure_ascii=False, indent=2),
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

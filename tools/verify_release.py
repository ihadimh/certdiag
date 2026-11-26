"""verify_release.py — 校验下载的发布包是否与 SHA256SUMS 一致

用法：
    python tools/verify_release.py dist/certdiag-portable.zip
    python tools/verify_release.py 包.zip --sums 别的SHA256SUMS.txt
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def load_sums(path: Path) -> dict[str, str]:
    sums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts[0].upper(), parts[1].strip().lstrip("*")
        sums[Path(name).name] = digest
    return sums


def verify(zip_path: Path, sums_path: Path) -> tuple[bool, str]:
    if not zip_path.is_file():
        return False, f"文件不存在：{zip_path}"
    if not sums_path.is_file():
        return False, f"SHA256SUMS 不存在：{sums_path}"
    expected = load_sums(sums_path).get(zip_path.name)
    if not expected:
        return False, f"{sums_path.name} 里没有 {zip_path.name} 的记录"
    actual = sha256_file(zip_path)
    if actual != expected:
        return False, f"哈希不匹配\n  期望：{expected}\n  实际：{actual}"
    return True, f"哈希一致：{actual}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="校验发布包与 SHA256SUMS 是否一致")
    ap.add_argument("zip", help="下载的 certdiag-portable.zip")
    ap.add_argument("--sums", help="SHA256SUMS.txt 路径（默认同目录）")
    args = ap.parse_args(argv)

    zip_path = Path(args.zip)
    sums_path = Path(args.sums) if args.sums else zip_path.parent / "SHA256SUMS.txt"
    ok, msg = verify(zip_path, sums_path)
    print(("[OK] " if ok else "[失败] ") + msg)
    if ok:
        print("\n下一步（可选）：验证 Sigstore 签名")
        print("  sigstore verify identity --certificate cert.pem --signature 包.sig \\")
        print("      --identity <sign-release.yml 的 workflow 身份> 包.zip")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

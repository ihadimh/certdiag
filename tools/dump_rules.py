"""dump_rules.py — 把归因规则导出成 rules.json

产物：
    docs/rules.json   供文档、其他工具、agent 消费

用法：
    python tools/dump_rules.py
"""

from __future__ import annotations

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

from certdiag.rules import RULES, as_json  # noqa: E402


def main() -> int:
    out = ROOT / "docs" / "rules.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(as_json(), encoding="utf-8")
    print(f"[+] {out}  ({out.stat().st_size} B, {len(RULES)} 条规则)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

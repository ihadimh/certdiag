"""sarif.py — 把诊断报告转成 SARIF 2.1.0

用途：让 GitHub Code Scanning / 安全仪表板直接消费归因结果。
只输出 invalid（error）与 unknown（warning），valid 不进 SARIF
（没有问题的文件不需要出现在告警列表里）。

设计取舍：
    - ruleId 直接用归因分类（如 catalog_covers_embedded_invalid），
      下游可以按分类写策略，而不是按文件路径。
    - properties 里保留 confidence / verdict / not_checked，
      SARIF 查看器不一定展示，但脚本可以读。
"""
from __future__ import annotations

import json
from pathlib import Path

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {"invalid": "error", "unknown": "warning"}

_HELP_BASE = "https://github.com/ihadimh/certdiag/blob/main/docs/CONFIDENCE.md"


def _file_uri(path: str) -> str:
    try:
        return Path(path).resolve().as_uri()
    except (OSError, ValueError):
        # 路径不存在 / 含非法字符时，退化成手工拼接，保证 SARIF 仍可用
        return "file:///" + str(path).replace("\\", "/")


def build_sarif(reports: list[dict], tool_version: str) -> dict:
    """把 build_report() 的产物列表转成 SARIF 文档。"""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for rep in reports:
        diag = rep.get("diagnosis") or {}
        verdict = diag.get("verdict")
        level = _LEVEL.get(verdict)
        if not level:
            continue

        category = diag.get("category") or "unknown"
        rules.setdefault(category, {
            "id": category,
            "name": category,
            "shortDescription": {"text": diag.get("cause") or category},
            "helpUri": f"{_HELP_BASE}#{category.lower().replace('_', '-')}",
        })

        path = (rep.get("file") or {}).get("path") or ""
        result = {
            "ruleId": category,
            "level": level,
            "message": {"text": diag.get("cause") or category},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _file_uri(path)},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "verdict": verdict,
                "confidence": diag.get("confidence"),
                "not_checked": diag.get("not_checked") or [],
                "category": category,
            },
        }
        hresult = (rep.get("signature") or {}).get("hresult")
        if hresult is not None:
            result["properties"]["hresult"] = f"0x{int(hresult):08X}"
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "certdiag",
                    "informationUri": "https://github.com/ihadimh/certdiag",
                    "version": tool_version,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def dump_sarif(reports: list[dict], tool_version: str, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_sarif(reports, tool_version), fh, ensure_ascii=False, indent=2)

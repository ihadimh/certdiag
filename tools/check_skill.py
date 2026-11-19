"""check_skill.py — 校验 SKILL.md 是否符合 DSH 的发现规则

DSH 扫描技能根目录时，只认这两种形态：
    <root>/<name>/SKILL.md    （目录包）
    <root>/<name>.md          （平铺文件）
嵌套的 **/SKILL.md 不会被发现。

frontmatter 必需 name 与 description；可选 whenToUse、metadata、
disable-model-invocation、user-invocable。

用法：
    python tools/check_skill.py                     # 检查默认技能根
    python tools/check_skill.py <目录或 SKILL.md>    # 检查指定路径
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

# DSH 的默认扫描根（按优先级从高到低）
ROOTS = [
    Path.home() / ".dsh" / "skills",
    Path.home() / ".agents" / "skills",
]

REQUIRED = ("name", "description")
OPTIONAL = ("whenToUse", "metadata", "disable-model-invocation", "user-invocable")
BOOL_KEYS = ("disable-model-invocation", "user-invocable")
TRUE_WORDS = {"true", "yes", "on", "1"}
FALSE_WORDS = {"false", "no", "off", "0"}


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """极简 YAML frontmatter 解析：只处理 key: value 与一级缩进块。"""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    block = text[3:end].strip("\n")
    body = text[end + 4:].lstrip("\n")

    meta: dict = {}
    key = None
    for raw in block.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0] not in " \t" and ":" in raw:
            key, _, val = raw.partition(":")
            key = key.strip()
            val = val.strip()
            meta[key] = val if val else {}
        elif key and isinstance(meta.get(key), dict):
            sub = raw.strip()
            if ":" in sub:
                k, _, v = sub.partition(":")
                meta[key][k.strip()] = v.strip()
    return meta, body


def check_one(path: Path) -> tuple[bool, str, dict]:
    """返回 (是否合法, 说明, 目录条目)。"""
    if path.is_dir():
        md = path / "SKILL.md"
        name_hint = path.name
    else:
        md = path
        name_hint = path.stem

    if not md.exists():
        return False, f"找不到 {md}", {}

    raw = md.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        # BOM 会让 frontmatter 的 "---" 前面多一个字符，解析直接失败
        return False, "文件带 UTF-8 BOM，frontmatter 会解析失败（另存为「UTF-8 无 BOM」）", {}
    text = raw.decode("utf-8", "replace")
    meta, body = parse_frontmatter(text)

    problems = []
    for k in REQUIRED:
        if not meta.get(k):
            problems.append(f"缺少必填字段 `{k}`")

    name = meta.get("name", "")
    if name and path.is_dir() and name != name_hint:
        problems.append(f"name「{name}」与目录名「{name_hint}」不一致，可能不被发现")

    desc = meta.get("description", "")
    if desc and len(desc) < 20:
        problems.append("description 太短，模型难以判断何时使用")

    for k in BOOL_KEYS:
        if k in meta:
            v = str(meta[k]).strip().lower()
            if v not in TRUE_WORDS | FALSE_WORDS:
                problems.append(f"`{k}` 值「{meta[k]}」不是合法布尔值（会导致整个 skill 被丢弃）")

    unknown = [k for k in meta if k not in REQUIRED + OPTIONAL]
    warn = f"（忽略未知字段：{', '.join(unknown)}）" if unknown else ""

    entry = {
        "path": str(md),
        "name": name,
        "description": desc,
        "whenToUse": meta.get("whenToUse", ""),
        "lines": len(body.splitlines()),
    }
    if problems:
        return False, "；".join(problems) + warn, entry
    return True, "格式正确" + warn, entry


def main(argv: list[str]) -> int:
    targets: list[Path] = []
    if len(argv) > 1:
        targets = [Path(a) for a in argv[1:]]
    else:
        for root in ROOTS:
            if not root.is_dir():
                continue
            for child in sorted(root.iterdir()):
                if child.is_dir() and (child / "SKILL.md").exists():
                    targets.append(child)
                elif child.suffix == ".md":
                    targets.append(child)

    if not targets:
        print("没有找到任何 skill。")
        print("默认扫描根：" + "、".join(str(r) for r in ROOTS))
        return 1

    ok_all = True
    print(f"检查 {len(targets)} 个 skill\n" + "=" * 70)
    for t in targets:
        ok, msg, entry = check_one(t)
        ok_all &= ok
        print(f"\n{'[OK]' if ok else '[!!]'} {entry.get('name') or t.name}")
        print(f"     路径：{entry.get('path', t)}")
        if ok:
            print(f"     描述：{entry['description'][:70]}")
            print(f"     正文：{entry['lines']} 行")
        else:
            print(f"     问题：{msg}")

    print("\n" + "=" * 70)
    print("全部通过，重启会话即可被 DSH 发现。" if ok_all else "存在格式问题，修好后重新检查。")
    return 0 if ok_all else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# -*- coding: utf-8 -*-
"""一次性修正 README 与打包脚本里的过期/矛盾内容。

发现的问题：
  1. 下载链接写死 1.5.0，实际最新是 2.1.1（且资产名带版本，链接必然过期）
  2. 性能章节自相矛盾：表格说 300 个 11.3 s，下面又说"12 个文件、加速只有 1.2 倍"
  3. 测试数量写 52（实际 121）
  4. 吊销三档的示例数字与现在的默认行为不符（默认已是 cache）
  5. Roadmap 里还写着"23 倍提速"，与第 2 条互相打脸
  6. build_portable 的使用说明写死 1.5.0，打出来的包自带错误版本号
"""
from pathlib import Path

ROOT = Path(r"C:\Users\ASUS\Documents\deepseek-harness\default-workspace\certdiag")
readme = ROOT / "README.md"
t = readme.read_text(encoding="utf-8")

# ---------- 1. 下载区：改成不随版本失效的链接 ----------
old_dl = """**[⬇ 下载 certdiag-portable-1.5.0.zip](https://github.com/ihadimh/certdiag/releases/download/v1.5.0/certdiag-portable-1.5.0.zip)**（约 11 MB，解压后**双击即用**，自带 Python 运行时）

```
certdiag-portable-1.5.0/
├── 双击启动.cmd      ← 打开图形界面（无黑框）
├── 命令行诊断.cmd    ← 把文件拖到它上面，直接出结论
├── runtime/          ← 自带 Python 3.12（embeddable）
├── certdiag/  docs/  samples/  tests/  tools/
└── verify.py  README.md  LICENSE
```"""
new_dl = """**[⬇ 下载最新便携版](https://github.com/ihadimh/certdiag/releases/latest)**（约 11 MB，解压后**双击即用**，自带 Python 运行时）

发布页里的 `certdiag-portable.zip` 永远是最新版，校验值在同页 `SHA256SUMS.txt`。
（早期版本用带版本号的文件名，导致 README 里的链接会过期；现在资产名固定，链接不会失效。）

```
certdiag-portable-<版本>/
├── 双击启动.cmd      ← 打开图形界面（无黑框）
├── 命令行诊断.cmd    ← 把文件拖到它上面，直接出结论
├── runtime/          ← 自带 Python 3.12（embeddable）
├── certdiag/  docs/  samples/  tests/  tools/
└── verify.py  README.md  LICENSE
```"""
assert old_dl in t, "下载区没匹配上"
t = t.replace(old_dl, new_dl)

# ---------- 2. 性能：删掉与表格矛盾的旧结论 ----------
old_perf = """> v2.1.1 把时间戳解析搬进常驻 worker，并把"整文件读入"改成"只读 PE 头 + 证书表"：
> 单个文件的令牌校验从 250~600 ms 降到 1~4 ms，300 个文件的批量从 77.6 s 降到 11.3 s。

> 测量条件：Windows 11 22621、`C:\\Windows\\System32\\*.dll` 取 12 个、跳过网络探测、冷/热缓存未区分。
> **加速比只有约 1.2 倍**——早期文档里的"103 s → 4.5 s（23×）"是另一次不同条件下的数字，
> 不应再引用。worker 的真正收益主要在 PowerShell 启动慢的机器上（冷启动、杀软扫描、组策略），
> 单文件场景几乎没有差别。要复测请用同一批文件、同一 `--no-probe` 设置。"""
new_perf = """> v1.9.0 把时间戳解析搬进常驻 worker，并把"整文件读入"改成"只读 PE 头 + 证书表"：
> 单个文件的令牌校验从 250~600 ms 降到 1~4 ms，300 个文件的批量从 77.6 s 降到 11.3 s（6.9×）。

> 测量条件：Windows 11 22621，`C:\\Windows\\System32` 下按文件名排序取 300 / 600 个 dll，
> `--no-probe`，缓存已热。**该数字不能直接套到单文件场景**——单文件主要是进程启动开销（约 2 s），
> 优化前后差别不大；批量才是 worker 的收益所在。要复测请用同一批文件、同一 `--no-probe` 设置。"""
assert old_perf in t, "性能段落没匹配上"
t = t.replace(old_perf, new_perf)

# ---------- 3. 测试数量 ----------
old_tests = """```bash
python -m unittest discover -s tests -v
# Ran 52 tests ... OK
```"""
new_tests = """```bash
python -m unittest discover -s tests -v
# Ran 121 tests ... OK

python tools/ui_selftest.py          # 界面 12 项 HTTP 自检
python verify.py                     # 121 个测试 + 3 个真实场景
```"""
assert old_tests in t, "测试段落没匹配上"
t = t.replace(old_tests, new_tests)

# ---------- 4. 吊销三档示例：用当前实测数字 ----------
old_rev = """同一个文件（Packet Tracer）三种档位的实际输出：

```
# off —— 2.7 秒，明确说没查
结论：✅ 有效 — 签名与证书链有效；未检查吊销状态（--revoke=off）
分类：valid_revocation_unchecked  置信度：medium
吊销：未检查（--revoke=off）

# cache —— 3.3 秒，本机缓存里没有 CRL 时应如实说"无法确认"
结论：⚠️ 无法判定 — 吊销状态未知（系统链报告 OfflineRevocation）
分类：revocation_unverified  置信度：medium
吊销：未检查（系统链报告 OfflineRevocation）

# auto —— 4.9 秒，探测到地址可达后真的联网查了
结论：✅ 有效 — 签名、证书链与吊销状态均已检查通过
分类：valid_revocation_checked_ok  置信度：high
吊销：已检查（正常）
```"""
new_rev = """同一个文件（Packet Tracer 9.0.1）三种档位的实际输出与耗时（三次取平均）：

```
# off —— 1.8 秒，明确说没查
结论：✅ 有效 — 签名与证书链有效；未检查吊销状态（--revoke=off）
分类：valid_revocation_unchecked  置信度：medium
吊销：未检查（--revoke=off）

# cache（默认）—— 2.3 秒，本机缓存里已有该 CA 的 CRL，命中即给结论
结论：✅ 有效 — 签名、证书链与吊销状态均已检查通过
分类：valid_revocation_checked_ok  置信度：high
吊销：已检查（正常）

# auto —— 2.1 秒，先探测地址可达，再联网查
结论：✅ 有效 — 签名、证书链与吊销状态均已检查通过
分类：valid_revocation_checked_ok  置信度：high
吊销：已检查（正常）
```

> `cache` 的结果取决于本机缓存：命中时给 `checked_ok`，未命中时如实写
> 「吊销：未检查（系统链报告 OfflineRevocation）」，分类 `revocation_unverified`。
> 这不是不稳定，而是「查到就说查到，没查到就说没查到」。"""
assert old_rev in t, "吊销示例没匹配上"
t = t.replace(old_rev, new_rev)

# ---------- 5. 已验证场景：补上新分类 ----------
old_cases = """| OCSP 端点拒绝 GET | 标记 `inconclusive`，不影响总体结论 |
| CPS 声明页超时 | **忽略**，不计入吊销失败（曾误报，已修复） |"""
new_cases = """| OCSP 端点拒绝 GET | 标记 `inconclusive`，不影响总体结论 |
| CPS 声明页超时 | **忽略**，不计入吊销失败（曾误报，已修复） |
| 文件内容被篡改 | `hresult:TRUST_E_BAD_DIGEST`，invalid，置信度 high |
| 自签名 / 内部 CA | `untrusted_root`，invalid，confidence high |
| 截断的 PE（节表越界） | `corrupt_pe`，unknown |
| 非 PE 内容 / 0 字节 | `not_pe_file`，unknown |
| 无签名且无目录覆盖 | `no_signature`，unknown |
| 中文路径、空格、方括号文件名 | 正常诊断（曾因 stdin 编码误报"文件不存在"） |"""
assert old_cases in t, "已验证场景没匹配上"
t = t.replace(old_cases, new_cases)

# ---------- 6. 已知限制：补上真实缺口 ----------
old_lim = """| 代理只读环境变量与 IE 设置 | 不解析 PAC 脚本，PAC 环境仍可能误判 | v3 支持 PAC |"""
new_lim = """| 代理只读环境变量与 IE 设置 | 不解析 PAC 脚本，PAC 环境仍可能误判 | v3 支持 PAC |
| 双签名（嵌套签名）只取第一个签名者 | 多签文件的证据不完整 | 见 issue #1 |
| 旧式 PKCS#9 countersignature 只记录不验签 | 老文件（如 d3dx9）显示 `expired_with_timestamp` | 见 issue #6 |
| 没有真实已吊销证书样本 | `revoked` 分支只有单元测试 | 见 issue #3 |"""
assert old_lim in t, "已知限制没匹配上"
t = t.replace(old_lim, new_lim)

# ---------- 7. Roadmap：修掉 "23 倍" ----------
old_road = """- [x] 常驻 PowerShell worker（23 倍提速）"""
new_road = """- [x] 常驻 PowerShell worker（批量 300 个：77.6 s → 11.3 s）"""
assert old_road in t, "Roadmap 没匹配上"
t = t.replace(old_road, new_road)

# 补几条已完成项
t = t.replace("""- [x] 时间戳令牌校验（SignedCms）
- [ ] C# 版本（单文件分发）""",
"""- [x] 时间戳令牌校验（SignedCms）
- [x] 证据层：证据 / 冲突 / 未验证清单 / 置信度依据
- [x] `--strict`：证据不足就判 unknown
- [x] 界面 12 项 HTTP 自检（并发、413、403）
- [x] Windows 10 虚拟机验收（100 个系统文件零误判）
- [ ] C# 版本（单文件分发）""")

readme.write_text(t, encoding="utf-8")
print("README 已修正 7 处")

# ---------- 8. build_portable：使用说明用版本号模板 ----------
bp = ROOT / "tools" / "build_portable.py"
t2 = bp.read_text(encoding="utf-8")
t2 = t2.replace('USAGE_TXT = r"""certdiag 1.5.0 便携版 · 使用说明',
                'USAGE_TXT = r"""certdiag {ver} 便携版 · 使用说明')
t2 = t2.replace("2. 打开解压出的文件夹 certdiag-portable-1.5.0",
                "2. 打开解压出的文件夹 certdiag-portable-{ver}")
bp.write_text(t2, encoding="utf-8")
print("build_portable 使用说明已改为模板")

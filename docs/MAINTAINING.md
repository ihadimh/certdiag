# 维护者手册

接手这个项目（或隔一段时间回来改）时，先看这一页。

## 当前版本

| 项 | 值 |
|---|---|
| 版本 | 唯一来源 `certdiag/__init__.py` 的 `__version__`（本文不重复写版本号） |
| 发布 | 资产固定命名 `certdiag-portable.zip`，README 指向 `/releases/latest` |
| 依赖 | 仅标准库 + Windows 自带 PowerShell |

## 数据流（改代码前先看这个）

| 阶段 | 代码 | 输入 → 输出 | 失败时 |
|---|---|---|---|
| 采集 | `collect.py` / `psworker.py` / `catalog.py` / `pe.py` / `timestamp.py` | 路径 → 原始信号 dict | 返回 `error`，`status` 为空 |
| 归因 | `attrib.py` | 原始信号 → 分类 / 结论 / 原因 / 建议 | 纯函数，不会失败 |
| 证据 | `evidence.py` | 原始信号 + 归因结果 → 信号 / 冲突 / 未验证 / 置信度 | 纯函数，不会失败 |
| 输出 | `report.py` / `cli.py` / `ui.py` | 报告对象 → 文本 / JSON / 页面 | — |

两条约束：

1. **采集失败必须走 `collect_failed`**，不能把"没有数据"解释成"结构不对"。
   2026-11-23 修过一次：文件被占用时报成了 `not_pe_file`（说内容不是 PE），
   实际只是读不到。
2. **证据层只能降置信度，不能升**。归因说 high，有冲突就压到 low；反之不允许。

调试：`python -m certdiag <文件> --trace` 会按上面的阶段打印实际取值。

## 能力边界

改行为前先读 [CAPABILITIES.md](CAPABILITIES.md)：它写了什么能做什么不能做、什么时候准什么时候不准。
改完如果能力有变化，那份文档也要跟着改。

## 三分钟验证

改完任何东西，跑这三条：

```powershell
python -m unittest discover -s tests     # 134 个用例
python verify.py                         # 4 个真实场景
python -m certdiag "C:\Windows\System32\cmd.exe" --no-probe
```

预期：

| 命令 | 预期 |
|---|---|
| unittest | `Ran 97 tests ... OK` |
| verify.py | 系统组件 / 篡改样本 / 原始副本 / 单元测试 四项 `[OK]` |
| cmd.exe | `catalog_only_trust`，结论句含「由有效的目录签名（catalog）覆盖」 |

再跑一次大规模批量（验证性能与稳定性，约 30 秒）：

```powershell
python -m certdiag "C:\Windows\System32" --no-probe -q
```

600 个文件应在 30 秒内完成，且不应出现 invalid（系统判定优先）。

再跑一次真实路径审计（会真的起 PowerShell、发网络请求，约 30 秒）：

```powershell
python tools/real_path_audit.py --fast
```

输出 `docs/audit-<时间>.json`。**新增采集入口时，必须在这里加一条**——
`--offline` 和批量流式两个缺陷都是纯函数测试抓不到的。

再抽两个边界样本：

```powershell
python -m certdiag samples\tampered.exe --no-probe   # hresult:TRUST_E_BAD_DIGEST / invalid
python -m certdiag "不存在的文件"                     # 退出码 3
```

## 版本号纪律

`certdiag/__init__.py` 的 `__version__` 是唯一来源，**提交信息里的版本号必须与它一致**。
曾出现过提交写 "v1.9.3"、代码仍是 1.9.0 的情况——发布前先核对：

```powershell
python -c "import certdiag; print(certdiag.__version__)"
```

## 发布流程

```
1. 改 certdiag/__init__.py 的 __version__
2. python tools/build_portable.py          # 生成 dist/certdiag-portable-<ver>.zip
3. 解压到干净目录，跑 runtime\python.exe verify.py
4. 打 tag、建 Release、上传 zip
5. 同步更新 docs/STATE 之类的手册与 README 里的下载链接
```

便携包会校验 `runtime\python.exe` 的 Authenticode 签名，不通过直接中止构建。

## 证据边界

**已验证**（改动后应保持成立）

| 主张 | 验证方式 |
|---|---|
| 目录签名能识别，且校验 `.cat` 自身状态 | cmd.exe → `catalog_only_trust` |
| 内容改动能识别 | tampered.exe → `hresult:TRUST_E_BAD_DIGEST` |
| 过期+时间戳降级正确 | signed_ok.exe → `expired_with_timestamp_signature_ok` / medium |
| 吊销检查能真的联网 | Packet Tracer + `--revoke=auto` → `valid_revocation_checked_ok` |
| 内网地址默认不探测 | `probe_url('http://127.0.0.1/...')` → `skipped_private` |
| 签名门禁能拦 | 未签名文件 + `--require-signature` → 退出码 1 |
| 错误码含义正确 | `certutil -error` 对照 `CODES` 表 |
| JSON 结构固定 | 单文件与多文件都是 `{schema_version, reports}` |

**未验证**（别当成结论说）

| 项 | 现状 |
|---|---|
| 真实「已吊销证书」样本 | `revoked` 分支只有构造输入验证 |
| 中间证书过期 / 尚未生效 | `NotTimeValid` 统一按签名者过期解释 |
| 企业代理环境 | 只测过直连，代理兜底未真机验证 |
| 非 Win11 环境 | 只在 Windows 11 22621 跑过 |
| WinVerifyTrust 慢网络 | 没有超时，可能在慢网络下卡住 |

## 不可破坏的约定

1. **`unknown ≠ invalid`**：查不到不等于有问题；默认 `--fail-on invalid`。
2. **结论必须可追溯**：说「有效」要能说清是签名通过、链通过，还是吊销也查了。
3. **只读**：不装证书、不改注册表、不绕过校验、默认不探测内网。
4. **判定顺序**：PE 结构 → 已吊销 → 强错误码 → 目录签名 → 时间/链 → 兜底。
   吊销和结构损坏必须排在有效期、时间戳之前。
5. **JSON 结构**：`{schema_version, tool, tool_version, generated_at, count, reports}`，不随条数变化。

违反上面任一条，测试可能还是绿的，但工具会开始给出错误结论。

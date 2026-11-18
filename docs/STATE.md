# 项目状态（STATE）

> 这份文件的用途：**给下一个会话的 AI 看**。
> 上下文会被压缩/重置，聊天记录留不住；这里记录"当前什么是真的、什么是没验证的"。
> 每次改动请更新「版本与验证」和「已知未修」两节。

最后更新：2026-11-18 · v1.5.0

## 一句话

Windows 代码签名诊断工具：把"签名无效"拆成可解释的结论，只读、零第三方依赖、有 CLI 和本地 Web 界面。

## 版本与发布

| 项 | 值 |
|---|---|
| 版本 | 1.5.0（唯一来源：`certdiag/__init__.py`） |
| 仓库 | https://github.com/ihadimh/certdiag （单提交、约 0 MB、43 文件 ~640 KB） |
| 发布 | Release v1.5.0，资产 `certdiag-portable-1.5.0.zip`（约 11 MB） |
| 技能包 | https://github.com/ihadimh/windows-signature-triage （一份 SKILL.md） |

## 验证过的事实（可以当成前提）

| 主张 | 怎么验的 |
|---|---|
| 86 个单元测试通过 | `python -m unittest discover -s tests` |
| 4 个真实场景自检通过 | `python verify.py`（系统组件/篡改样本/原始副本/单元测试） |
| 目录签名能被识别 | `cmd.exe` → `catalog_only_trust / valid`，且会校验 `.cat` 自身状态 |
| 篡改能被识别 | `samples/tampered.exe` → `hresult:TRUST_E_BAD_DIGEST / invalid` |
| 过期+时间戳降级正确 | `signed_ok.exe` → `expired_with_timestamp_signature_ok / medium` |
| `--revoke=auto` 真能联网查 | Packet Tracer → `valid_revocation_checked_ok`，约 4.9s |
| 内网地址默认不探测 | `probe_url('http://127.0.0.1:8765/x.crl')` → `skipped_private` |
| `--require-signature` 能拦 | 未签名 txt：默认退出 0，加参数退出 1 |
| CI 双版本通过 | GitHub Actions，Python 3.10 / 3.12 |

## 没验证过的事（别当成结论说）

| 未验证 | 风险 |
|---|---|
| 真实「已吊销证书」样本 | `revoked` 分支**从未被真实数据触发过**，只测过构造输入 |
| 中间证书过期 / 尚未生效 | `NotTimeValid` 只按"签名者过期"解释，未区分层级 |
| 企业代理环境 | 只测过直连；代理兜底路径没有真机验证 |
| 非 Win11 环境 | 只在 Windows 11 22621 上跑过 |
| WinVerifyTrust 卡死场景 | 没有超时机制，未在慢网络下测试 |
| GUI 的吊销档位 | 界面没有 `--revoke` 选项，固定 off |

## 三条不变量（改动时不能破坏）

1. **`unknown ≠ invalid`**：查不到 ≠ 有问题。默认 `--fail-on invalid`，`unknown` 不算失败。
2. **结论必须能追溯到证据**：说"有效"就要说清是签名通过、链通过，还是吊销也查了。
3. **只读**：不装证书、不改注册表、不绕过校验、不上传文件、默认不探测内网。

## 关键文件

```
certdiag/attrib.py     归因引擎（所有结论的出处）
certdiag/revoke.py     吊销四档策略
certdiag/timestamp.py  时间戳令牌校验（PS + SignedCms）
certdiag/catalog.py    目录签名反查
certdiag/winverify.py  WinVerifyTrust（ctypes）
certdiag/probe.py      CRL/OCSP 可达性探测（含内网拦截）
certdiag/ui.py         本地 Web 界面
certdiag/rules.py      24 条规则（与报告标签有覆盖测试）
tests/                 86 个用例，其中 5 个真调 Windows API
```

# 置信度与边界

这张表回答一个问题：**报告里的结论，到底能拿它做什么？**

三值结论（`valid` / `invalid` / `unknown`）是"文件状态"；
置信度只描述"证据够不够"，不描述"文件好坏"。
**`medium` 不等于 `high`，不能直接写进自动阻断策略。**

## 分类对照表

| 分类 | 置信度 | 证明了什么 | **没有**证明什么 | 需要复核时 |
|---|---|---|---|---|
| `valid_revocation_checked_ok` | high | 签名、证书链、吊销都查过且通过 | — | — |
| `valid` | high | 系统判定有效，且证据一致 | 吊销是否真的查过（看 `revocation`） | — |
| `valid_offline` | medium | 链与有效期有效 | **吊销状态完全没查** | 联网重跑，或看 `not_checked` |
| `catalog_only_trust` | high | 文件哈希命中目录，`.cat` 自身签名有效 | 完整 `WinVerifyTrust` 目录语义 | `signtool verify /pa` |
| `catalog_signed` | high | 嵌入式签名有效，且被目录覆盖 | 同上 | `signtool verify /pa` |
| `expired_with_timestamp_signature_ok` | **medium** | 令牌自身签名完整 | **messageImprint 绑定、TSA 链与用途、签发时刻有效性** | `signtool verify /pa /t` |
| `expired_with_timestamp` | **medium** | 文件带时间戳，系统可能据此判有效 | 令牌未校验 | `signtool verify /pa /t` |
| `catalog_unverified` | unknown | 找到了 `.cat`，但无法验证其签名 | 目录是否可信 | 换权限/环境重跑 |
| `revoked` | high | 证书被吊销（强否定） | — | — |
| `hash_mismatch` | high | 文件内容与签名不匹配 | 是"被篡改"还是"传输损坏" | 与官方哈希对比 |
| `untrusted_root` | high | 根证书不在本机信任列表 | 根是否在企业策略里被显式信任 | 部署根证书后重跑 |
| `partial_chain` | high | 缺中间证书，链不完整 | 证书本身是否有效 | 安装中间证书 |
| `key_usage` | high | 证书用途不含代码签名 | — | — |
| `expired` | high | 证书不在有效期，且无可用时间戳 | — | 核对系统时间 |
| `wrong_usage` | medium | EKU 与操作不匹配 | 是否存在其他可用签名 | `signtool verify /pa /v` |
| `malformed_signature` | medium | WinVerifyTrust 拒绝签名结构 | 是否被篡改（也可能是未公开的 PE 标记检查） | `signtool verify /pa /v` |
| `unexplained_hresult` | low | 只有一个未收录的 HRESULT | 任何根因 | 带 `--json` 提 issue |
| `revocation_unverified` / `revocation_unreachable` | medium | 地址可达性探测失败/无结论 | 证书是否被吊销 | 换网络或代理后重跑 |
| `revocation_not_checked` | medium | 显式离线，未查 | 同上 | 去掉 `--offline` |
| `catalog_covers_embedded_invalid` | **low** | 嵌入式签名无效，但目录签名覆盖 | 该信哪一边 | 人工复核，不要自动放行 |
| `no_signature` | medium | 没有嵌入式签名，也没有目录覆盖 | 文件是否可信 | 看来源渠道 |
| `not_pe_file` / `corrupt_pe` | medium | 扩展名与内容不符 / PE 结构不完整 | 原始文件是否正常 | 重新获取文件 |
| `collect_failed` | low | 读不到文件 | 任何签名信息 | 解决占用/权限后重跑 |
| `not_applicable` | medium | 该类型没有 Authenticode 概念 | — | — |
| `unknown` | low | 现有信息不足 | 任何结论 | 带报告提 issue |

> 完整分类见 [`rules.json`](rules.json)；未实现的检查见 [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md)。

## 门禁建议

| 场景 | 推荐参数 | 说明 |
|---|---|---|
| 只想拦"确定无效" | `--fail-on invalid` | 默认；`unknown` 不会让流水线变红 |
| 要拦"无法判定" | `--fail-on unknown --strict` | 证据不足会降级为 `unknown` |
| 发布门禁最终裁决 | **不要只用本工具** | 时间戳链、TSA 用途、完整目录语义仍需 `signtool verify /pa /t` |

**一条硬规则**：`medium` 和 `unknown` 只能触发"人工复核"或"告警"，不能触发"自动放行"。

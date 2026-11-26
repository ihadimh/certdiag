# 常见签名错误对照表

先看 `certdiag` 的**分类**，再看 HRESULT。
同一个错误码可能对应完全不同的原因——这正是本工具存在的理由。

| HRESULT / 现象 | 字面意思 | 常见真实原因 | certdiag 分类 | 详细 |
|---|---|---|---|---|
| `0x800B0100` `TRUST_E_NOSIGNATURE` | 没有签名 | 文件本来没签；**或签在 `.cat` 目录里** | `no_signature` / `catalog_only_trust` | [看这页](errors/no-signature.md) |
| `0x800B0109` `CERT_E_UNTRUSTEDROOT` | 根不受信任 | 自签名、企业根未部署、根证书被删 | `untrusted_root` | [看这页](errors/untrusted-root.md) |
| `0x800B010A` `CERT_E_CHAINING` | 链构建失败 | 缺中间证书、系统时间错、AIA 下载失败 | `partial_chain` | [看这页](errors/partial-chain.md) |
| `0x800B010C` `CERT_E_REVOKED` | 证书已吊销 | 证书泄露/违规被 CA 吊销 | `revoked` | [看这页](errors/revoked.md) |
| `0x80096010` `TRUST_E_BAD_DIGEST` | 哈希不匹配 | 文件被改过，或下载/复制损坏 | `hash_mismatch` | [看这页](errors/bad-digest.md) |
| `0x80096011` `TRUST_E_MALFORMED_SIGNATURE` | 签名结构不被接受 | PE 标记不规范、签名工具异常、未公开的 relaxed marker 检查 | `malformed_signature` | [看这页](errors/malformed-signature.md) |
| `0x800B0110` `CERT_E_WRONG_USAGE` | 用途不匹配 | 用服务器/邮件证书签代码 | `wrong_usage` | [看这页](errors/wrong-usage.md) |
| `0x80092013` `CRYPT_E_REVOCATION_OFFLINE` | 吊销状态拿不到 | 内网/代理/断网；CRL 地址被墙 | `revocation_unreachable` | [看这页](errors/revocation-offline.md) |
| `0x800B010D` `CERT_E_UNTRUSTEDTESTROOT` | 链终止于测试根 | 用了测试/内部 CA，根未部署 | `untrusted_root` | [看这页](errors/untrusted-root.md) |
| `0x800B0111` `TRUST_E_EXPLICIT_DISTRUST` | 被显式不信任 | 证书被列入不信任列表 | `revoked` / `untrusted_root` | [看这页](errors/revoked.md) |

## 按分类

| 分类 | 说明 |
|---|---|
| `catalog_only_trust` | [只有目录签名](errors/catalog-only-trust.md) |
| `expired_with_timestamp*` | [证书过期但带时间戳](errors/expired-with-timestamp.md) |
| `revocation_unreachable` | [吊销状态拿不到](errors/revocation-offline.md) |

## 三个最常见的误判

| 误判 | 实际情况 | 怎么区分 |
|---|---|---|
| "PowerShell 说 Valid 但 WinVerifyTrust 报 0x800B0100，文件有问题" | 文件签名在 `.cat` 目录里，不是嵌在 PE 里 | 看报告是否 `catalog_only_trust` |
| "查不到吊销 = 证书无效" | 多半是网络/代理到不了 CRL/OCSP | 看 `revocation` 的探测结果；`unknown ≠ invalid` |
| "证书过期 = 签名失效" | 带可信时间戳的签名在签发时刻仍有效 | 看是否 `expired_with_timestamp*`；用 `signtool /t` 复核 |

## 相关

- [`CONFIDENCE.md`](CONFIDENCE.md)：每个分类的置信度与边界
- [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md)：本工具尚未覆盖的检查

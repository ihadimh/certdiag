# 0x80092013 CRYPT_E_REVOCATION_OFFLINE

**现象**：证书链有效，但「吊销状态无法获取」；内网/代理环境最常见。

**常见原因**

1. CRL/OCSP 地址不可达（被墙、代理、DNS）
2. 离线机器
3. 证书里的 CDP 地址本身失效

**怎么区分**

- certdiag 分类 `revocation_unreachable` / `revocation_unverified` / `revocation_not_checked`
- 看报告里每个 CRL/OCSP 的 DNS/TCP/HTTP 探测结果

**下一步**

- 换网络或配代理后重跑 `--revoke=auto`
- **不要**把「查不到」判成「证书无效」

相关：[置信度表](../CONFIDENCE.md) · [错误索引](../ERRORS.md)

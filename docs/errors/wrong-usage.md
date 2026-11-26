# 0x800B0110 CERT_E_WRONG_USAGE

**现象**：证书有效、链完整，但「用途不匹配」。

**常见原因**

1. 用服务器/邮件/客户端证书签代码
2. 证书 EKU 不含 Code Signing
3. 证书被限制用途（如仅限文档签名）

**怎么区分**

- certdiag 分类 `wrong_usage`
- `certutil -dump 证书.cer` 看 EKU（1.3.6.1.5.5.7.3.3 = Code Signing）

**下一步**

- 换正确的代码签名证书
- 不要用 `-f` 强制签，签名能生成但验证会失败

相关：[置信度表](../CONFIDENCE.md) · [错误索引](../ERRORS.md)

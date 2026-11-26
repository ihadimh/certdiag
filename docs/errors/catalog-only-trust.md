# 只有目录签名（catalog）

**现象**：文件没有嵌入式签名，但 Windows 认为签名有效；`WinVerifyTrust` 可能报 `TRUST_E_NOSIGNATURE`。

**为什么会这样**

系统文件常把签名放在 `.cat` 目录里，PE 本身不带签名。`Get-AuthenticodeSignature` 会回退到目录，
`WinVerifyTrust` 不会——于是两个 API 给出相反结论。

**certdiag 会怎么判**

- 找到 `.cat` 且其签名有效 → `catalog_only_trust`，high
- 找到但 `.cat` 签名无法验证 → `catalog_unverified`，unknown
- 文件哈希不在目录里 → 不会误报为有效

**它没证明什么**

- 完整 `WinVerifyTrust` 目录语义（成员属性、策略）
- `.cat` 的签发者是否在你的信任范围

**下一步**

- `signtool verify /pa /v 文件` 复核
- 不要因为「没有嵌入式签名」就替换系统文件

相关：[置信度表](../CONFIDENCE.md) · [错误索引](../ERRORS.md)

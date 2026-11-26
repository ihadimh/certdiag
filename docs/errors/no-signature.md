# 0x800B0100 TRUST_E_NOSIGNATURE

**现象**：`signtool verify` 报 `No signature found`；文件属性 → 数字签名 是空的；
PowerShell `Get-AuthenticodeSignature` 返回 `NotSigned`。

**常见原因**

1. 文件确实没签名（自己编译的、绿色版、下载后被打包工具改过）
2. 签名不在 PE 里，而在**目录（`.cat`）**里——系统文件非常常见
3. 签名格式不被当前 API 支持（少见）

**怎么区分**

- 看 certdiag 报告有没有「目录签名」一行：有 → `catalog_only_trust`
- 命令行复核：`signtool verify /pa /v 文件.exe`，看是否走 catalog

**下一步**

- 有目录签名：正常，不要重装/替换文件
- 真没签：看来源渠道；与官方公布的哈希对比

相关：[置信度表](../CONFIDENCE.md) · [错误索引](../ERRORS.md)

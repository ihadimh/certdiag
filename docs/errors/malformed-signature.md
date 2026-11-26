# 0x80096011 TRUST_E_MALFORMED_SIGNATURE

**现象**：签名结构不被 WinVerifyTrust 接受；文件可能完全正常。

**常见原因**

1. PE 标记不规范（某些打包/加壳工具）
2. 签名工具异常或签名被截断
3. **未公开的 relaxed PE marker 检查**（WDAC 相关）

**怎么区分**

- certdiag 分类 `malformed_signature`，**判 unknown，不判 invalid**
- `signtool verify /pa /v` 看具体失败步骤
- 换一台机器/换一个签名工具重新签，观察是否复现

**下一步**

- 不要仅凭这个码判「文件被篡改」
- 用标准工具重新签名后再验

相关：[置信度表](../CONFIDENCE.md) · [错误索引](../ERRORS.md)

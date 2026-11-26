# 0x800B010A CERT_E_CHAINING

**现象**：提示「无法构建证书链」；证书本身可能完全有效。

**常见原因**

1. 缺中间证书（打包工具裁掉了链）
2. 系统时间不正确
3. AIA（证书下载地址）不可达

**怎么区分**

- certdiag 分类 `partial_chain`；`chain.built=false`
- `certutil -verify` 会指出缺失的颁发者

**下一步**

- 安装对应中间证书（通常签发者官网提供）
- 核对系统时间；代理环境检查 AIA 是否可达

相关：[置信度表](../CONFIDENCE.md) · [错误索引](../ERRORS.md)

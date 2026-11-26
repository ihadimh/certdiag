# 证书已过期，但带时间戳

**现象**：签名者证书已过期，但签名带有时间戳；系统可能仍判有效。

**certdiag 会怎么判**

- `expired_with_timestamp_signature_ok`：令牌签名有效，**medium**
- `expired_with_timestamp`：只看到时间戳，未验令牌，**medium**
- `expired`：无可用时间戳，**invalid**

**它没证明什么**

- messageImprint 是否对应当前文件签名
- TSA 证书是否带时间戳用途 EKU
- TSA 链在签发时刻是否有效

**下一步**

- 需要最终结论时：`signtool verify /pa /t 文件`
- 不要仅凭 `medium` 做发布门禁

相关：[置信度表](../CONFIDENCE.md) · [错误索引](../ERRORS.md)

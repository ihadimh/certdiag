# 真实路径审计报告

日期：2026-11-19
版本：v1.6.3 → v1.6.4
方法：逐条调用真实入口（起 PowerShell / 调 WinVerifyTrust / 发 HTTP 请求），共 34 项。
脚本：`tools/real_path_audit.py`（明细写入 `docs/audit-<时间>.json`）

## 一、结论先说

**34 项全部没有抛异常，但发现 4 个会让功能失效的缺陷，其中 1 个从实现起就是坏的。**

| # | 缺陷 | 影响 | 状态 |
|---|---|---|---|
| 1 | HTTP chunked 分帧写成了字面量 `\r\n` | **批量扫描流式输出从未可用**（客户端解析失败） | 已修 |
| 2 | `--offline` 参数绑定失败（`[bool]` 收字符串） | 离线模式下一次性采集**整条失败** | 已修（v1.6.3） |
| 3 | `DisableCertificateDownloads` 在 PS 5.1 不存在 | 离线 worker **整条失败** | 已修（v1.6.3） |
| 4 | 输入不存在/是目录时仍触发 worker→一次性回退 | 白等 300~500 ms，且错误被二次覆盖 | 已修（v1.6.4） |

## 二、缺陷 1：批量扫描一直是坏的

`certdiag/ui.py` 的 `_chunk`：

```python
# 修复前（源码里就是两个反斜杠）
self.wfile.write(("%x\\r\\n" % len(data)).encode() + data + b"\\r\\n")
```

发出的字节是 `<hex>\\r\\n<data>`，不是合法的 chunked 分帧。任何按规范解析的客户端都会失败：

```
http.client.IncompleteRead: IncompleteRead(0 bytes read)
PowerShell Invoke-WebRequest: 无法从传输连接中读取数据: 连接已关闭
```

`git log -L` 显示：这行代码在**引入它的那次提交里就是这样**。也就是说，

> 仓库历史上的批量流式输出**没有任何一个版本真正可用**。

需要说明一个无法回避的矛盾：`docs/ui-batch.png` 展示了批量进度条。按这份代码，
浏览器不可能渲染出那个界面——那张图要么来自未提交的中间版本，要么是示意。
**这类"看起来验证过"的材料，以后不能作为功能可用的证据。**

修复后实测（2 个样本）：

```
#1/2 expired_with_timestamp_signature_ok -> valid
#2/2 hresult:TRUST_E_BAD_DIGEST -> invalid
done: {'total': 2, 'valid': 1, 'invalid': 1, 'unknown': 0, 'elapsed': 1.35}
```

## 三、缺陷 2、3：`--offline` 让采集整条挂掉

| 路径 | 现象 | 根因 |
|---|---|---|
| 一次性 | `ParameterArgumentTransformationError` | `[bool]$Offline` 收到的是字符串 `"true"` |
| worker | `找不到属性 DisableCertificateDownloads` | 该属性在 .NET Framework 4.8 不存在 |

修复：
- 参数改 `[string]`，脚本内比较 `'true'`
- 赋值前探测属性是否存在，并把结果写进 `aia_downloads_disabled`

**连带发现的诚实问题**：SECURITY.md 原来写"离线会关闭 AIA 下载"，在 PS 5.1 上是假的。
已改为条件式说明，并让报告如实输出该字段。

## 四、缺陷 4：回退条件过宽

旧逻辑：worker 返回任何 `error` 都回退到一次性进程。
但"文件不存在""这是目录"是**输入问题**，回退没有意义——白等 300~500 ms，
而且会把原始错误换成 PowerShell 的原始报错。

修复后：

```
collect.missing     0 ms   文件不存在
collect.directory   0 ms   这是目录，请对单个文件诊断（或使用批量扫描）
```

同时给 worker 的错误加了 `error_kind`（`not_found` / `is_directory` / 内部故障），
只有内部故障才触发回退。

## 五、验证通过的项（没有发现问题）

| 项 | 结果 |
|---|---|
| worker 被杀后恢复 | `status=Valid`，回退 1 次，1.6 s 内恢复 |
| 内网地址拦截 | `skipped_private` |
| 公网 CRL 探测 | `ok`，892 ms |
| OCSP 端点 | `inconclusive`（不判为不可达） |
| 截断 PE / 0 字节 / 非 PE | `corrupt_pe` / `not_pe_file`，不崩 |
| 文件名含空格 / `[ ]` / 中文 | 正常诊断（PS 用 `-LiteralPath`） |
| 被独占锁定的文件 | 正常返回，不崩 |
| 上传后临时文件 | 无残留 |
| 伪造 Host / Origin | 403 |
| 扫描目录（UI） | 200 +「这是目录，请使用批量扫描」 |
| `--json` 结构 | 顶层 6 键，单/多文件一致 |

## 六、耗时基线（本机 Windows 11 22621）

| 项 | 耗时 |
|---|---|
| worker 首次采集（含启动） | ~530 ms |
| worker 后续采集 | ~19 ms |
| 一次性采集（每次起 PowerShell） | ~545 ms |
| WinVerifyTrust（单独调用） | 1~18 ms |
| 目录签名反查 | ~3 ms |
| 时间戳令牌校验 | ~230~260 ms |
| 网络探测（单个地址） | 4~900 ms（取决于目标） |

## 七、仍存在的问题（未修）

| 问题 | 说明 |
|---|---|
| 超大请求体返回连接重置而非 413 | 服务端先拒绝、但客户端此时仍在发送，看到的是连接中断 |
| `chain.built=false` 时吊销状态不可用 | 证书过期时链构建失败，吊销检查无从谈起（语义正确，但报告不够醒目） |
| 批量无并发 | 逐文件串行；大目录耗时随文件数线性增长 |
| UI 无 token | 有 Host/Origin 校验，但本机非浏览器进程可直接调用 |

## 八、复跑方式

```powershell
python tools/real_path_audit.py          # 全量（含联网）
python tools/real_path_audit.py --fast   # 跳过联网与 online 吊销
```

输出 `docs/audit-<时间>.json`，可直接与上一次对比。

# 真实路径测试清单

目的：**每个采集入口都真的跑一次**。纯函数测试喂的是"我想象中的输入"，
而实际会出问题的地方通常在"输入拿不到"这一层——`--offline` 就是这么挂掉的。

## 采集层

| # | 入口 | 预期 |
|---|---|---|
| 1 | `collect(cmd.exe)` 默认（worker） | `status=Valid`，含 `sha256/signer/chain` |
| 2 | `collect(cmd.exe, offline=True)` | 同上，且 `aia_downloads_disabled` 有值 |
| 3 | `_collect_subprocess(cmd.exe)` 一次性 | 同上 |
| 4 | `_collect_subprocess(..., offline='true')` | 同上 |
| 5 | `collect(cmd.exe, revoke='Offline')` | 链策略生效，不抛异常 |
| 6 | `collect(cmd.exe, revoke='Online')` | 慢但成功（允许超时） |
| 7 | `collect(不存在的路径)` | 返回 `error`，不抛异常 |
| 8 | `collect(目录)` | 返回 `error`，不崩 |
| 9 | worker 被杀后再次 collect | 自动回退一次性，仍拿到结果 |

## 签名与目录

| # | 入口 | 预期 |
|---|---|---|
| 10 | `winverify.verify(cmd.exe, revoke='off')` | `0x800B0100`（目录签名） |
| 11 | `winverify.verify(tampered.exe)` | `0x80096010` |
| 12 | `winverify.verify(签名文件, revoke='cache')` | 不抛异常，有 hresult |
| 13 | `catalog.find_catalog(cmd.exe)` | 找到 `.cat`，状态 `Valid` |
| 14 | `catalog.find_catalog(未签名临时文件)` | `found=false` |
| 15 | `catalog.find_catalog(不存在路径)` | 返回 error，不抛 |

## 时间戳

| # | 入口 | 预期 |
|---|---|---|
| 16 | `timestamp.verify(signed_ok.exe)` | `token_ok=true`，有 TSA |
| 17 | `timestamp.verify(cmd.exe)` | `has_signature=false` |
| 18 | `timestamp.verify(截断的 PE)` | 有明确 error，不崩 |
| 19 | `timestamp.verify(不存在)` | error 文本 |
| 20 | `timestamp.verify(0 字节文件)` | error，不崩 |

## 网络探测

| # | 入口 | 预期 |
|---|---|---|
| 21 | `probe_url(http://127.0.0.1:8765/x.crl)` | `skipped_private` |
| 22 | `probe_url(公网可访问地址)` | `ok` |
| 23 | `probe_url(非法 URL)` | 不抛异常，有 category |
| 24 | `probe_url(不存在域名)` | `dns_fail` |
| 25 | `probe_url(ocsp 端点)` | `inconclusive` 或 `ok` |

## 端到端

| # | 入口 | 预期 |
|---|---|---|
| 26 | `diagnose_one(签名文件, offline)` | 分类合理，有 signals |
| 27 | `diagnose_one(tampered)` | `invalid` |
| 28 | `--json` 单文件 | 顶层 6 个键 |
| 29 | `--require-signature` 对未签名文件 | 退出码 1 |
| 30 | 不存在的路径 | 退出码 3 |

## 边界输入

| # | 输入 | 预期 |
|---|---|---|
| 31 | 0 字节 `.exe` | `not_pe_file`，不崩 |
| 32 | 截断 PE | `corrupt_pe` |
| 33 | 文本内容但 `.dll` 扩展名 | `not_pe_file` |
| 34 | 文件名含空格 | 正常诊断 |
| 35 | 文件名含 `[ ]` 通配符字符 | 正常诊断（PS 用 `-LiteralPath`） |
| 36 | 中文文件名 | 正常诊断 |
| 37 | 被独占锁定的文件 | 有明确 error，不崩 |

## Web UI（HTTP 层）

| # | 请求 | 预期 |
|---|---|---|
| 38 | `GET /api/health` | 200 |
| 39 | `POST /api/scan` 合法文件 | 200 + diagnosis |
| 40 | `POST /api/scan` 不存在路径 | 200 + error 字段（不是 500） |
| 41 | `POST /api/batch` 目录 | NDJSON 流，末行 `done` |
| 42 | `POST /api/export` | 返回附件 |
| 43 | 伪造 Host | 403 |
| 44 | 伪造 Origin | 403 |
| 45 | `POST /api/scan` 超大 body | 拒绝（8 MB 上限） |
| 46 | 上传 200MB+ 文件 | 拒绝（上限） |

## 记录方式

每条记录：**入口 / 输入 / 耗时 / 关键字段 / 是否异常**。
异常 = 抛异常、返回结构缺字段、结论与预期不符、耗时异常（>30s）。

# 代码审计记录（2026-11-24）

范围：`certdiag/` 全部 11 个模块、`tools/` 8 个脚本、`verify.py`。
方法：静态扫描（AST + 正则找高风险写法）＋ 构造输入的真实运行（不是只读代码）。

## 一、已修复的问题

| # | 现象 | 根因 | 修复 |
|---|---|---|---|
| 1 | `--md` 导出直接崩溃（NameError） | Markdown 渲染里混入了控制台渲染的变量 `out`，应为 `lines`，且整段被贴到了"目录签名"小节 | 移到"一、结论"并改名 |
| 2 | `--json` / `--md` 写到不可写路径时抛 traceback | `dump_json` / `write_text` 未捕获 `OSError` | 捕获后打印明确错误，退出码 3 |
| 3 | `Origin: http://127.0.0.1`（不带端口）被放行 | `u.port in (None, port)` 把"没写端口"当成任意端口 | 按 80 处理，端口必须一致 |
| 4 | 畸形 Origin（`http://127.0.0.1:8765.evil.com`）让鉴权函数抛 `ValueError` | 访问 `u.port` 未捕获异常 | 捕获后返回 False |
| 5 | `GET /` 不校验 Host，DNS rebinding 可读到页面 | 只给 POST 加了 `_trusted_caller` | 抽出 `_host_allowed`，GET 也校验 |
| 6 | 扫描含 junction 环的目录会无限递归 | `Path.rglob` 会跟随重解析点 | 改 `os.walk` + 目录 `(st_dev, st_ino)` 去重 |
| 7 | 上传文件名原样回显（可含 `..\`、控制字符） | `X-Filename` 未清洗 | 取 basename + 过滤不可打印字符 |
| 8 | `esc()` 不转义引号 | 只转义了 `& < >` | 补 `"` 和 `'` |
| 9 | 无 worker 时时间戳/一次性采集可能卡死 | 仍用 `tempfile.mkstemp`（部分环境 O_EXCL 卡住） | 统一走探测过的可写目录 + `open('w')` |

每一类都在 `tests/test_audit.py` 里有回归用例（共 5 组）。

## 二、检查过但判定"可接受"的

| 项 | 评估 |
|---|---|
| `probe.py` 的 SSRF 防护 | 解析后判私网、禁跟随 3xx、协议只认 http(s)。**残留**：DNS rebinding 的 TOCTOU（先解析判公网、连接时再解析）理论上可绕过；证书里的地址本来就不可信，风险低，`--allow-private` 已提供显式开关 |
| `tools/real_path_audit.py` 的 `os.system("taskkill ...")` | PID 来自 `subprocess.Popen`，不是用户输入；且该脚本不随便携包分发 |
| `psworker.py` 里的 `assert` | 只用于内部不变量；`python -O` 下会消失，但随后会抛更明确的异常，不产生安全问题 |
| 38 处 `except ...: pass` | 逐处看过：临时文件清理、浏览器打开、代理读取等"失败也不该中断诊断"的路径。采集主路径已经用 `error_kind` 区分，不会把"没拿到"当成"没有" |
| `esc()` 之外的 `innerHTML` | 所有来自报告/证书/文件名的字段都经过 `esc()`；`vbadge` 的 `x.text` 来自固定表，服务端 verdict 只有三种取值 |

## 三、没有覆盖到的

- **DNS rebinding 的完整防护**（需要固定解析结果并直连 IP，改动面较大）
- **并发压力**（UI 是 ThreadingHTTPServer，只测了 8 并发，没有长时间压测）
- **超大文件**（>2 GB 的 PE 没有构造样本；时间戳有 512 MB 上限保护）
- **Windows 之外的平台**（工具本身就只支持 Windows）

## 四、怎么复现这次审计

```powershell
python -m unittest discover -s tests        # 270 个用例
python tools/check_docs.py -v               # 文档一致性 9 组
python verify.py                            # 真实场景自检
```

针对性的手工验证：

```powershell
# 1) Markdown 导出
python -m certdiag C:\Windows\System32\cmd.exe --md out.md

# 2) 不可写路径
python -m certdiag C:\Windows\System32\cmd.exe --json C:\Windows\System32\x.json
# 期望：打印「无法写入 JSON 报告」，退出码 3

# 3) junction 环（需要 cmd 的 mklink /J）
```

## 四之二、覆盖情况（2026-11-24 二轮）

补了 CLI 入口、控制台渲染、本地探测的测试后：

```
总行覆盖：2456/2694 = 91.2%（270 个用例）
```

仍未覆盖的主要是：超时/代理分支、需要真实吊销样本的分支、UI 的 serve 生命周期。

## 五、结论

- 没有发现远程代码执行、权限提升、任意文件写入的路径
- UI 只监听 127.0.0.1，鉴权依赖 Host + Origin + Sec-Fetch-Site，已修复两处绕过
- 主要风险仍然是"误判"和"卡死"，本次各修掉一批；`KNOWN_ISSUES.md` 里保留了做不到的部分

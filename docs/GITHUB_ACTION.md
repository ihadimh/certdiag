# 在 GitHub Actions 中使用

certdiag 是 Windows 工具，Action 必须跑在 `windows-latest` 上。

## 最小示例

```yaml
name: signature-check
on: [push, pull_request]

jobs:
  certdiag:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: 签名归因
        uses: ihadimh/certdiag@v2.4.0
        with:
          paths: dist
          fail-on: invalid
          args: "--no-probe"

      - name: 上传 SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: certdiag.sarif
```

Action 直接使用自身源码目录（`github.action_path`），**不需要 pip 安装，也不额外联网**。

## 输入

| 输入 | 默认 | 说明 |
|---|---|---|
| `paths` | 必填 | 文件或目录；多个用空格分隔，含空格时加引号 |
| `fail-on` | `invalid` | `invalid` / `unknown` / `none` |
| `args` | `--no-probe` | 额外参数，如 `--strict --revoke=auto` |
| `sarif` | `certdiag.sarif` | SARIF 输出路径 |

## 退出码与门禁

| 退出码 | 含义 |
|---|---|
| 0 | 全部有效 |
| 1 | 存在无效（`fail-on invalid`） |
| 2 | 存在无法判定（`fail-on unknown`） |
| 3 | 运行错误 |

推荐组合：

- **只拦确定无效**：`fail-on: invalid`（默认）
- **连"无法判定"一起拦**：`fail-on: unknown` + `args: "--strict --no-probe"`

> `medium` / `unknown` 只应触发人工复核，不要自动放行。详见 [`CONFIDENCE.md`](CONFIDENCE.md)。

## 本地等价命令

```powershell
python -m certdiag .\dist --no-probe --fail-on invalid --sarif certdiag.sarif
```

## 局限

- 只支持 Windows runner（PowerShell + WinVerifyTrust）
- Action 只是 CLI 的包装；时间戳链、TSA 用途、完整目录语义的边界见 [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md)

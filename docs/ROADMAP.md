# Roadmap：从诊断工具到归因原语

## 最终成果（定义完成的三个指标）

1. **被调用**：至少 1 个外部仓库在 CI 里使用 Action，或 `from certdiag import attribute`；有公开链接。
2. **可信**：时间戳 `messageImprint` 绑定 + TSA 链/用途补齐，或明确保持 `medium` 并禁止自动放行；发布资产 Sigstore + Authenticode。
3. **可维护**：库 API 有 semver 与弃用策略；干净 Windows 上 `pip install` 验证通过；发布自动化（测试 → 构建 → 签名 → release）。

> 不是"功能更多的工具"，而是"签名故障现场的第一跳"。

## 里程碑

| # | 目标 | 内容 | 工作量 | 依赖 | 状态 |
|---|---|---|---|---|---|
| M1 | 打包与 API 验证 | 干净 Windows `pip install`；`--version`；semver/弃用策略；wheel | 2–3 天 | 无 | 待做 |
| M2 | 标注语料 + 基准 | 每类 10+ 样本；precision/recall；`docs/BENCHMARK.md` | 1 周 | 真实样本（issue #3） | 待做 |
| M3 | 时间戳绑定 + TSA 链 | `messageImprint`、TSA EKU、签发时刻链；关键分类升到 `high` | 2–4 周 | ASN.1/CMS + 样本 | 待做 |
| M4 | 目录完整语义 | `WINTRUST_CATALOG_INFO` 成员校验；明确"信系统"边界 | 1–2 周 | Windows API 细节 | 待做 |
| M5 | Authenticode 签名 | 自己的启动器 exe + SignPath / Azure Trusted Signing | 代码 2–3 天；等待 2–6 周 | 证书/审核 | 待做 |
| M6 | 外部采用 | 1 个外部仓库用 Action；1 个库用户；一篇真实案例 | 不可控 | 真实需求 | 待做 |
| M7 | 发布与维护自动化 | changelog、release notes 模板、issue triage | 持续 | 无 | 进行中 |

## 已完成（截至 v2.4.0）

- 归因引擎 31 分类 + 证据层（冲突 / 未检查 / 置信度）
- CLI / JSON / Markdown / SARIF
- 库入口 `certdiag.attribute()`
- GitHub Action（真实 Windows runner 自测通过）
- Sigstore 签名（release 附带 `.sigstore.json`）
- 文档：`CONFIDENCE.md`、`ERRORS.md` + 10 个错误分页
- 286 个测试，行覆盖 90.7%

## 不做

- 改名、买搜索广告、社区刷推荐
- 接 Velociraptor / SOAR（Action 已是最小可行）
- 扩格式（MSI/PS1/容器）——先把归因深度补齐
- 加 GUI 功能——UI 不是护城河

---
name: Bug 报告
about: 结论不对、崩溃、输出异常——请带上环境与完整输出
title: "[bug] "
labels: bug
assignees: ''
---

## 一句话

<!-- 例如：cmd.exe 被判成 invalid，但系统显示有效 -->

## 环境

| 项 | 值 |
|---|---|
| certdiag 版本 | <!-- `python -m certdiag --version` 或包内 使用说明.txt --> |
| Windows 版本 | <!-- winver 里的，例如 Windows 10 22H2 19045.5073 --> |
| PowerShell 版本 | <!-- `$PSVersionTable.PSVersion` --> |
| 运行方式 | <!-- 便携包 / pip 安装 / 源码 --> |
| 特殊环境 | <!-- 代理、离线、受限 PowerShell、杀软拦截 --> |

## 复现命令

```powershell
# 原样贴出来，包括参数
python -m certdiag "C:\path\to\file.exe" --no-probe
```

## 实际输出

```
# 贴完整输出，不要只贴"结论"那一行
# 如果方便，贴 --json 的结果（记得删掉路径里的用户名）
```

## 期望结果

<!-- 你认为应该判成什么，依据是什么 -->

## 你验证过什么

<!-- 跑了什么命令、对比了什么输出、有没有换台机器复核 -->

## 交叉验证

<!-- 有则更好：sigcheck -a / signtool verify / Get-AuthenticodeSignature 的结果 -->

## 其他

<!-- 文件来源（官方下载 / 自己编译 / 内部系统）、是否可公开样本 -->

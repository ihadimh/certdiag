# 发布签名与校验

## 现状

| 项 | 状态 |
|---|---|
| SHA256 校验和 | ✅ 每个 release 附带 `SHA256SUMS.txt` |
| Sigstore 无密钥签名 | ✅ 手动 workflow（`.github/workflows/sign-release.yml`） |
| Windows Authenticode 签名 | ⏳ 未签（需要证书，见下） |

## 为什么还没有 Authenticode

便携包不是单个 exe，而是「脚本 + 自带 Python 运行时」。要给用户看到“已验证的发布者”，
需要一个**自己的签名 exe 启动器**（例如 PyInstaller 打包），再用代码签名证书签名。
当前优先级：先把归因逻辑做对；证书准备走 SignPath Foundation（开源项目免费）或
Azure Trusted Signing。

在此之前，**不要**用自签名证书冒充可信发布者——那只会多一个“未知发布者”。

## 校验下载（所有人都能做）

```powershell
python tools/verify_release.py certdiag-portable.zip
# 或
Get-FileHash certdiag-portable.zip -Algorithm SHA256
# 与 SHA256SUMS.txt 里的值对比
```

## 验证 Sigstore 签名

维护者手动触发 `sign-release` workflow 后，release 里会出现 `.sig` 与 `.crt`：

```bash
sigstore verify identity \
  --certificate certdiag-portable.zip.crt \
  --signature  certdiag-portable.zip.sig \
  --identity   "https://github.com/ihadimh/certdiag/.github/workflows/sign-release.yml@refs/heads/main" \
  --issuer     "https://token.actions.githubusercontent.com" \
  certdiag-portable.zip
```

> Sigstore 证明的是“这个文件由这个 workflow 构建/签名”，**不证明**文件里的代码没有 bug；
> Authenticode 证明的是“发布者身份”。两者互补，不能互相替代。

## 发布检查清单

- [ ] `python -m unittest discover -s tests` 通过
- [ ] `python tools/check_docs.py` 通过
- [ ] 版本号与 `certdiag/__init__.py` 一致
- [ ] `tools/build_portable.py` 产物完整性级别为 Medium（v2.3.1 起自动设置）
- [ ] 生成 `SHA256SUMS.txt` 并上传
- [ ] （可选）运行 `sign-release` workflow 生成 Sigstore 签名

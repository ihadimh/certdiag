# 虚拟机验收记录（Windows 10）

这是**第一次在非开发机**上跑完整流程的验收记录。
环境：Windows 10（用户虚拟机），通过 `certdiag-vm-kit.zip` 自带运行时运行，
未安装 Python、未安装 Git。

## 一、执行内容

双击 `双击运行自测.cmd`，脚本依次执行：

1. `verify.py` —— 单元测试 + 3 个真实场景
2. `tools/build_corpus.py` —— 从本机 System32/drivers/SysWOW64 生成语料
3. 批量扫描 `corpus/signed`
4. 扫描 `corpus/edge-cases` 与 `corpus/synthetic`

## 二、结果

### 1. 自检

```
Ran 121 tests in 8.445s
OK

[OK] 系统组件（仅目录签名）   cmd.exe → valid (catalog_only_trust)        2228 ms
[OK] 篡改样本（必须判无效）   tampered.exe → invalid (TRUST_E_BAD_DIGEST) 2044 ms
[OK] 原始副本（应为有效）     signed_ok.exe → valid (expired_with_timestamp_signature_ok) 2068 ms

体检报告：4 项全部 [OK]
```

### 2. 语料

```
System32/dll  取 30 / 3241
System32/exe  取 30 / 576
drivers/sys   取 30 / 413
SysWOW64/dll  取 30 / 200
完成：129 个文件，39.2 MB

catalog_only_trust                   88
expired_with_timestamp_signature_ok  32
corrupt_pe                            4
not_pe_file                           2
no_signature                          1
untrusted_root                        1
hresult:TRUST_E_BAD_DIGEST            1
```

### 3. 批量扫描（100 个系统文件）

```
共 100 个文件：有效 100  无效 0  无法判定 0
```

**零误判**——这是本报告最重要的一条。

### 4. 边界与合成样本

| 样本 | 分类 | 判定 |
|---|---|---|
| `a b c.exe`（空格名） | `corrupt_pe` | unknown（该样本是截断副本，见下节说明） |
| `not-a-pe.dll` | `not_pe_file` | unknown |
| `tampered.exe` | `hresult:TRUST_E_BAD_DIGEST` | **invalid** |
| `truncated.exe` | `corrupt_pe` | unknown |
| `x[1].dll` | `corrupt_pe` | unknown |
| `zero.exe` | `not_pe_file` | unknown |
| `中文 文件.exe` | `corrupt_pe` | unknown |
| `selfsigned.exe` | `untrusted_root` | **invalid**（high） |
| `unsigned.exe` | `no_signature` | unknown |

## 三、这次验收暴露并修掉的 4 个问题

| # | 现象 | 根因 | 修复 |
|---|---|---|---|
| 1 | 自检在 `samples/make_test_samples.py` 处崩溃 | 便携包未包含 `samples/`；且样本生成器只认 `git.exe` | 包里补 `samples/`；`verify.py` 缺样本时跳过；生成器加回退链（git → 运行时 python.exe → 扫 System32 找嵌入式签名） |
| 2 | `truncated.exe` 报 `no_signature` | `pe.py` 只校验证书表边界，不校验节表 | 新增节表边界校验（`PointerToRawData + SizeOfRawData` 越界）→ `corrupt_pe` |
| 3 | `tampered.exe` 报 `no_signature` | 基底是目录签名文件，改完只是"没签名" | 改用 `samples/tampered.exe`（改 `.text` 段，必出 `BAD_DIGEST`） |
| 4 | 启动脚本报 `'语料' 不是内部或外部命令` | `echo` 行的中文被 cmd 误解析 | 重写脚本输出行 |

另外两处后续调整：

- 文件名样本（中文/空格/方括号）原来用"截断到 64KB"的副本，被判成 `corrupt_pe`——
  测到的是截断而不是文件名。已改为完整副本，现在正确判为 `catalog_only_trust`。
- 启动脚本不再自动打开结果目录。

## 四、覆盖情况

| 场景 | 覆盖 | 说明 |
|---|---|---|
| 目录签名 | ✅ 88 个 | 系统组件的主形态 |
| 过期证书 + 时间戳 | ✅ 32 个 | 老系统组件 |
| 文件损坏（节表越界） | ✅ 4 个 | 生成样本 |
| 无签名 | ✅ | 生成样本 |
| 非 PE 内容 | ✅ | 生成样本 |
| 自签名（根不受信） | ✅ | 自建证书 |
| 内容被篡改 | ✅ | 改 `.text` 段 |
| 已吊销 | ❌ | 需要真实被吊销的证书 |
| 缺中间证书（`partial_chain`） | ❌ | 需要自建两级 CA |
| 时间戳绑定 / TSA 链 | ❌ | 需要完整 CMS 链校验（已知未做） |

## 五、与宿主机的对比

| 项 | 宿主机 Windows 11 22621 | 虚拟机 Windows 10 |
|---|---|---|
| 批量 100 个 | 全部 valid | 全部 valid |
| 目录签名 / 篡改 / 时间戳 | 通过 | 通过 |
| 单文件耗时 | 约 40 ms | 约 2 s（虚拟机较慢，符合预期） |
| 结论一致性 | — | **一致** |

说明判定逻辑不依赖具体 Windows 版本。

## 六、复现方式

```powershell
# 在任意 Windows 10/11 上
Expand-Archive certdiag-vm-kit.zip -DestinationPath D:\vm-kit
cd D:\vm-kit
.\双击运行自测.cmd
```

或只生成语料：

```powershell
.\runtime\python.exe tools\build_corpus.py --limit 120 --out .\corpus
.\runtime\python.exe -m certdiag .\corpus\signed --no-probe -q
```

## 七、结论

核心功能在 Windows 10 上可用，**100 个系统文件零误判**，边界样本分类符合预期。
剩余 2 类场景（已吊销、缺中间证书）需要有专门的 PKI 环境，不属于"代码改一改"能解决的。

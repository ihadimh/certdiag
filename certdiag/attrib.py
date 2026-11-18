"""attrib.py — 归因引擎

把"签名状态 + 证书链标志 + 探测结果"翻译成一句人话根因 + 处置建议。
这是整个工具的核心：不做归因，就只是把 certutil 的输出换个包装。

设计原则：
1. 只回答"最可能的原因是什么"，并给出置信度，不假装确定；
2. 优先区分"证书问题 / 网络问题 / 无法判定"三类，避免把网络故障说成证书失效；
3. 规则按"具体 → 笼统"排列，第一条命中的生效。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .revoke import label as revoke_label

# ---------------------------------------------------------------- 错误码映射
# 说明：Windows 的 WinVerifyTrust 返回 HRESULT。这里收录常见且确定的取值，
# 用于在拿到原始错误码时补充解释；未收录的码一律走"未知错误"分支。
HRESULT_MAP: dict[int, tuple[str, str]] = {
    0x800B0100: ("TRUST_E_NOSIGNATURE", "文件没有签名，或签名格式不被支持"),
    0x800B0101: ("CERT_E_EXPIRED", "证书已过期"),
    0x800B0109: ("CERT_E_UNTRUSTEDROOT", "根证书不受信任或不在信任库中"),
    0x800B010A: ("CERT_E_CHAINING", "无法构建到受信任根的证书链"),
    0x800B010C: ("CERT_E_REVOKED", "证书已被吊销"),
    0x800B010D: ("CERT_E_UNTRUSTEDTESTROOT", "证书链终止于“测试根”，该根不在生产信任范围"),
    0x80092013: ("CRYPT_E_REVOCATION_OFFLINE", "吊销状态无法获取（CRL/OCSP 离线或不可达）"),
    0x800B010E: ("CERT_E_REVOCATION_FAILURE", "吊销检查失败"),
    0x800B0111: ("TRUST_E_EXPLICIT_DISTRUST", "该证书被显式标记为不信任"),
    0x80096010: ("TRUST_E_BAD_DIGEST", "文件内容与签名不匹配（被修改或损坏）"),
    0x800B0004: ("TRUST_E_SUBJECT_NOT_TRUSTED", "签名主体不被信任"),
    0x800B0003: ("TRUST_E_SUBJECT_FORM_UNKNOWN", "签名主体格式未知"),
}

# 证书链标志 → 含义（.NET ChainStatus 名称）
CHAIN_FLAG_MAP: dict[str, str] = {
    "NotTimeValid": "证书不在有效期内（已过期或尚未生效）",
    "UntrustedRoot": "根证书不被信任（缺少根证书，或根被移出信任库）",
    "PartialChain": "证书链不完整（中间证书缺失）",
    "OfflineRevocation": "吊销服务器不可达，无法确认是否被吊销",
    "RevocationStatusUnknown": "吊销状态未知",
    "RevocationUnknown": "吊销状态未知",
    "InvalidBasicConstraints": "基本约束非法（CA/路径长度不符）",
    "InvalidKeyUsage": "密钥用法不符（该证书不能用于代码签名）",
    "InvalidNameConstraints": "名称约束非法",
    "InvalidPolicyConstraints": "策略约束非法",
    "NotValidForUsage": "证书用途与该操作不匹配",
    "HasNotSignature": "证书没有签名",
    "UnspecifiedError": "未指定的链错误",
}

VERDICT_VALID = "valid"
VERDICT_INVALID = "invalid"
VERDICT_UNKNOWN = "unknown"


@dataclass
class DiagInput:
    status: str = ""                 # Authenticode 状态（Valid / NotSigned / HashMismatch / NotTrusted ...）
    status_message: str = ""
    chain_flags: list[str] = field(default_factory=list)
    element_flags: list[str] = field(default_factory=list)
    signer_expired: bool = False
    timestamp_present: bool = False
    probes: list[dict] = field(default_factory=list)
    offline: bool = False
    hresult: int | None = None
    catalog: dict = field(default_factory=dict)
    timestamp: dict = field(default_factory=dict)
    revocation: dict = field(default_factory=dict)
    pe: dict = field(default_factory=dict)


@dataclass
class Diagnosis:
    category: str
    verdict: str
    cause: str
    confidence: str                        # high / medium / low
    advice: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _flags(inp: DiagInput) -> set[str]:
    return set(inp.chain_flags) | set(inp.element_flags)


HARD_FAIL = ("dns_fail", "blocked", "tls_error", "http_error")


def _net_problems(probes: list[dict]) -> list[dict]:
    """硬失败：可以确定"这个地址现在访问不到"。"""
    return [p for p in probes if p.get("category") in HARD_FAIL]


def _inconclusive(probes: list[dict]) -> list[dict]:
    """无结论：例如用 GET 探测 OCSP 端点，失败不能说明不可达。"""
    return [p for p in probes if p.get("category") == "inconclusive"]


def _hosts(probes: list[dict]) -> str:
    names = [p.get("host") or p.get("url", "") for p in probes if p.get("host")]
    return "、".join(dict.fromkeys(names))[:120]


def diagnose(inp: DiagInput) -> Diagnosis:
    st = (inp.status or "").strip()
    flags = _flags(inp)
    bad = _net_problems(inp.probes)
    # 只有 CRL / OCSP 地址的失败才与"吊销状态"有关；
    # CPS 声明页、证书下载地址（AIA）访问失败不影响吊销判断。
    bad = [p for p in bad if p.get("kind") in ("crl", "ocsp", None)]
    # OCSP 端点用 GET 探测失败是常态，不能与 CRL 不可达等同看待
    bad_crl = [p for p in bad if p.get("kind") != "ocsp"]
    bad_ocsp = [p for p in bad if p.get("kind") == "ocsp"]
    evidence = [f"Authenticode 状态：{st or '未知'}"]
    if inp.status_message:
        evidence.append(f"系统消息：{inp.status_message}")
    if flags:
        evidence.append("证书链标志：" + "、".join(sorted(flags)))
    if bad:
        evidence.append(f"吊销查询失败：{_hosts(bad)}")

    # -2) PE 结构本身有问题：这比"有没有签名"更靠前
    #     Get-AuthenticodeSignature 对损坏/截断的 exe 只会给 UnknownError 或 NotSigned，
    #     直接按状态归因会把"文件坏了"说成"这个类型没有签名概念"。
    pe_info = inp.pe or {}
    if pe_info and st != "Valid":
        if not pe_info.get("is_pe"):
            return Diagnosis(
                category="not_pe_file", verdict=VERDICT_UNKNOWN,
                cause="扩展名是程序文件，但内容不是有效的 PE 结构（可能已损坏或改了扩展名）",
                confidence="medium",
                advice=["重新获取该文件，先排除下载不完整",
                        "如果确实不是程序，改成正确的扩展名再看"],
                evidence=evidence + [f"PE 检测：{pe_info.get('reason') or '非 PE'}"])
        if pe_info.get("truncated"):
            return Diagnosis(
                category="corrupt_pe", verdict=VERDICT_UNKNOWN,
                cause="PE 结构不完整（文件可能被截断或损坏），无法判断签名",
                confidence="medium",
                advice=["重新下载或从原始介质复制该文件",
                        "哈希对不上原始发布值时，优先怀疑传输/存储损坏"],
                evidence=evidence + [f"PE 检测：{pe_info.get('reason') or '结构异常'}"])

    # -1) 已吊销：强否定证据，必须先于有效期/时间戳等一切分支
    #     理由：证书被吊销后，"签名时刻有效"不再成立，不能被时间戳分支判成 valid
    rev_early = inp.revocation or {}
    chain_flags_early = set(inp.chain_flags)
    if rev_early.get("state") == "revoked" or "Revoked" in chain_flags_early:
        return Diagnosis(
            category="revoked", verdict=VERDICT_INVALID,
            cause="证书已被吊销（签名者证书或链上证书出现在 CRL/OCSP 吊销列表中）",
            confidence="high",
            advice=["不要运行该文件；从官方渠道重新获取",
                    "若确认是误吊销，联系签发机构核实"],
            evidence=evidence + ["吊销检查：已吊销"])

    # 0) 只有这三种码能单独定性；其余交给"状态 + 链 + 探测"交叉判断
    #    （WinVerifyTrust 只看嵌入式签名，对目录签名文件会返回 NOSIGNATURE，
    #     不能直接据此判无效）
    STRONG_CODES = {0x800B010C, 0x800B0111, 0x80096010}
    if inp.hresult in STRONG_CODES and inp.hresult in HRESULT_MAP:
        name, desc = HRESULT_MAP[inp.hresult]
        return Diagnosis(
            category=f"hresult:{name}", verdict=VERDICT_INVALID, cause=desc,
            confidence="high",
            advice=["该错误码含义明确，按描述定位即可",
                    "如需进一步确认，可查看报告的证书链与探测结果"],
            evidence=evidence + [f"HRESULT 0x{inp.hresult:08X} = {name}"])

    if inp.hresult not in (None, 0) and inp.hresult not in STRONG_CODES:
        nm = HRESULT_MAP.get(inp.hresult, ("UNKNOWN", ""))[0]
        evidence.append(f"WinVerifyTrust：0x{inp.hresult:08X} {nm}")

    # 0.5) 系统判定有效，但文件自身无嵌入式签名 → 信任来自目录签名
    if st == "Valid" and inp.hresult == 0x800B0100 and (inp.catalog or {}).get("found"):
        cat = inp.catalog
        status = cat.get("signature_status")
        cat_ev = evidence + [f"目录签名状态：{status}",
                             f"目录文件：{cat.get('path')}"]
        # 关键：found 只说明"目录库里有条哈希对上了"，不代表这条 .cat 的签名可信。
        # 必须看 .cat 自身的签名状态，否则等于把"找到"当成"可信"。
        if status == "Valid":
            return Diagnosis(
                category="catalog_only_trust", verdict=VERDICT_VALID,
                cause="文件自身没有嵌入式签名，由有效的目录签名（catalog）覆盖",
                confidence="high",
                advice=["这是系统组件的常见形态，不需要处理",
                        "如需核对，可查看报告中的目录签名路径"],
                evidence=cat_ev)
        if status in ("HashMismatch",):
            return Diagnosis(
                category="catalog_hash_mismatch", verdict=VERDICT_INVALID,
                cause="目录文件的签名无效（.cat 内容与签名不符）",
                confidence="medium",
                advice=["目录可能被篡改或损坏，先跑 sfc /scannow",
                        "确认该 .cat 的来源"],
                evidence=cat_ev)
        return Diagnosis(
            category="catalog_unverified", verdict=VERDICT_UNKNOWN,
            cause=f"文件由目录签名覆盖，但目录签名状态为「{status or '未知'}」，无法确认有效性",
            confidence="medium",
            advice=["用 signtool verify /pa <目录文件> 复核",
                    "检查对应根证书是否在信任库中"],
            evidence=cat_ev)

    # 1) 没有嵌入式签名 —— 先查是否由目录签名覆盖
    if st in ("NotSigned", "NotSupportedFileFormat"):
        cat = inp.catalog or {}
        if cat.get("found"):
            sig_status = cat.get("signature_status")
            cat_path = cat.get("path") or ""
            cat_signer = cat.get("signer") or ""
            base_ev = evidence + [f"目录文件：{cat_path}", f"目录签名状态：{sig_status or '未知'}"]
            if sig_status == "Valid":
                return Diagnosis(
                    category="catalog_signed", verdict=VERDICT_VALID,
                    cause="文件本身无嵌入式签名，但由有效的目录签名（catalog）覆盖",
                    confidence="high",
                    advice=["这是系统文件的正常形态，不是「未签名」",
                            "如需核对签名者，查看报告中的目录签名信息"],
                    evidence=base_ev + ([f"签名者：{cat_signer}"] if cat_signer else []))
            if sig_status in ("HashMismatch",):
                return Diagnosis(
                    category="catalog_hash_mismatch", verdict=VERDICT_INVALID,
                    cause="目录签名存在，但目录本身的签名无效（内容与签名不符）",
                    confidence="medium",
                    advice=["目录文件可能被修改或损坏，用 sfc /scannow 修复系统文件",
                            "确认 .cat 是否来自可信来源"],
                    evidence=base_ev)
            return Diagnosis(
                category="catalog_unverified", verdict=VERDICT_UNKNOWN,
                cause=f"文件由目录签名覆盖，但目录签名状态为「{sig_status or '未知'}」，无法确认有效性",
                confidence="medium",
                advice=["用 signtool verify /pa <目录文件> 复核",
                        "检查该 .cat 对应的根证书是否在信任库中"],
                evidence=base_ev)
        return Diagnosis(
            category="no_signature", verdict=VERDICT_UNKNOWN,
            cause="文件既没有嵌入式签名，也没有找到覆盖它的目录签名",
            confidence="high",
            advice=[
                "确认是否为系统文件：系统文件通常由 .cat 覆盖，若未找到可能是系统目录损坏",
                "可用 sigcheck -a <文件> 交叉验证 Catalog 字段",
                "第三方程序的未签名状态属正常现象，不等于被篡改",
            ],
            evidence=evidence)

    # 2) 内容被改动
    if st == "HashMismatch" or inp.hresult == 0x80096010:
        return Diagnosis(
            category="hash_mismatch", verdict=VERDICT_INVALID,
            cause="文件内容与签名不匹配——文件被修改、损坏或替换过",
            confidence="high",
            advice=[
                "重新从官方渠道获取该文件",
                "比对文件哈希与官方公布值",
                "若做过脱壳/汉化/打补丁，签名失效属预期行为",
            ],
            evidence=evidence)

    # 3) 吊销相关（最容易误判为"证书坏了"的一类）
    revocation_flags = {"OfflineRevocation", "RevocationStatusUnknown", "RevocationUnknown"}
    # 链上已有确定的失败（根不受信 / 链不完整）时，先报那个，别被"网络问题"盖住
    certain_chain_failures = {"UntrustedRoot", "PartialChain"}
    if flags & revocation_flags and not (flags & certain_chain_failures):
        if bad_crl:
            kinds = {p.get("category") for p in bad_crl}
            kind_txt = {
                "dns_fail": "DNS 解析失败",
                "blocked": "TCP 连接被阻断或拒绝",
                "tls_error": "TLS 握手失败（可能被中间设备拦截）",
                "http_error": "HTTP 层返回异常",
            }
            desc = "、".join(kind_txt.get(k, str(k)) for k in kinds if k)
            return Diagnosis(
                category="revocation_unreachable", verdict=VERDICT_UNKNOWN,
                cause=f"证书本身未必有问题：吊销查询地址不可达（{desc}）",
                confidence="high",
                advice=[
                    "换一个能出网的网络环境重试，或配置系统代理后重试",
                    "离线/内网环境可临时关闭吊销检查（仅用于排查，不建议长期关闭）",
                    "手动下载对应 CRL 并导入：certutil -addstore CA <crl 文件>",
                    "判断影响：吊销状态无法确认 ≠ 证书已失效",
                ],
                evidence=evidence + [f"{p.get('url')} → {p.get('detail')}" for p in bad_crl][:6])
        rev_reason = (inp.revocation or {}).get("reason") or ""
        if bad_ocsp or _inconclusive(inp.probes) or rev_reason:
            return Diagnosis(
                category="revocation_unverified", verdict=VERDICT_UNKNOWN,
                cause=(f"吊销状态未知（{rev_reason}）" if rev_reason else
                       "吊销状态未能验证：CRL 地址可达，但 OCSP 端点无法用普通 GET 判定（属正常）"),
                confidence="medium",
                advice=[
                    "换用 --revoke=auto 让工具先探路再联网查，或用 signtool verify /pa /v 复核",
                    "以系统实际验证结果为准",
                    "若系统持续报 OfflineRevocation，再按「吊销地址不可达」处理",
                ],
                evidence=evidence)
        if inp.offline:
            return Diagnosis(
                category="revocation_not_checked", verdict=VERDICT_UNKNOWN,
                cause="以离线模式运行，未查询吊销状态",
                confidence="high",
                advice=["去掉 --offline 重新运行以获得吊销结论",
                        "离线结论只能证明「链与时间有效」，不能证明「未被吊销」"],
                evidence=evidence)
        return Diagnosis(
            category="revocation_unknown", verdict=VERDICT_UNKNOWN,
            cause="吊销状态未知（CRL/OCSP 查询未返回有效结果）",
            confidence="medium",
            advice=["检查证书中的 CDP/AIA 地址是否可从本机访问",
                    "确认系统时间正确——时间偏差会导致吊销查询失败"],
            evidence=evidence)

    # 4) 链不完整 / 根不受信
    if "UntrustedRoot" in flags:
        return Diagnosis(
            category="untrusted_root", verdict=VERDICT_INVALID,
            cause="根证书不受信任：本机信任库中没有该根，或根被显式移除",
            confidence="high",
            advice=[
                "确认该根证书是否为企业内部 CA，需要安装到「受信任的根证书颁发机构」",
                "若是公共 CA，检查系统根证书是否被精简或过期",
                "不要为了「让它通过」而随意安装来源不明的根证书",
            ],
            evidence=evidence)

    if "PartialChain" in flags:
        return Diagnosis(
            category="partial_chain", verdict=VERDICT_INVALID,
            cause="证书链不完整：缺少中间证书，链无法连到根",
            confidence="high",
            advice=["安装缺失的中间证书（通常可从签发者官网下载）",
                    "确认文件签名时是否附带完整证书链（部分打包工具会裁掉中间证书）"],
            evidence=evidence)

    # 5) 时间问题
    if "NotTimeValid" in flags or inp.signer_expired:
        ts = inp.timestamp or {}
        if ts.get("token_ok"):
            tsa = (ts.get("tsa_subject") or "").split(",")[0].replace("CN=", "")
            tsa_to = (ts.get("tsa_not_after") or "")[:10]
            return Diagnosis(
                category="expired_with_timestamp_signature_ok",
                verdict=VERDICT_VALID if st == "Valid" else VERDICT_UNKNOWN,
                cause="签名者证书已过期；时间戳令牌的签名有效（TSA 信任链与用途未校验）",
                confidence="medium",
                advice=["这只能证明令牌本身没被篡改，不等于「可信时间戳」",
                        f"时间戳由 {tsa or '未知 TSA'} 签发" + (f"（TSA 证书有效期至 {tsa_to}）" if tsa_to else ""),
                        "需要完整结论时用 signtool verify /pa /t（会校验 TSA 链与用途）"],
                evidence=evidence + [
                    f"时间戳令牌：验证通过（{ts.get('token_oid') or 'RFC3161'}）",
                    f"TSA：{ts.get('tsa_subject') or '未知'}",
                ])
        if ts.get("has_token") and not ts.get("token_ok"):
            return Diagnosis(
                category="expired_with_broken_timestamp",
                verdict=VERDICT_UNKNOWN,
                cause="签名者证书已过期，且时间戳令牌校验未通过——无法确认签名在签发时有效",
                confidence="medium",
                advice=["时间戳可能被篡改或损坏，建议从官方渠道重新获取文件",
                        "不要仅凭「文件能打开」就认为完整"],
                evidence=evidence + [f"时间戳：{ts.get('error') or '令牌签名校验失败'}"])
        if inp.timestamp_present:
            return Diagnosis(
                category="expired_with_timestamp",
                verdict=VERDICT_VALID if st == "Valid" else VERDICT_UNKNOWN,
                cause="签名者证书已过期，但签名带时间戳——按签名时刻评估可能仍然有效",
                confidence="medium",
                advice=["时间戳令牌未做校验，结论为推测",
                        "用 --timestamp 强制校验，或 signtool verify /pa /t"],
                evidence=evidence)
        return Diagnosis(
            category="expired", verdict=VERDICT_INVALID,
            cause="证书不在有效期内（已过期或系统时间不正确）",
            confidence="high",
            advice=["先核对本机系统时间是否准确",
                    "若证书确已过期且无时间戳，需重新签名"],
            evidence=evidence)

    # 6) 用途不符
    if flags & {"NotValidForUsage", "InvalidKeyUsage"}:
        return Diagnosis(
            category="key_usage", verdict=VERDICT_INVALID,
            cause="证书用途与该操作不匹配（例如用服务器证书签代码）",
            confidence="high",
            advice=["确认签名时使用的是代码签名证书（EKU 含 Code Signing）"],
            evidence=evidence)

    # 7) 签名有效
    if st == "Valid":
        rev = inp.revocation or {}

        # 吊销检查真的做过，且结论为已吊销 —— 直接定性
        if rev.get("state") == "revoked":
            return Diagnosis(
                category="revoked", verdict=VERDICT_INVALID,
                cause="证书已被吊销（签名者证书或链上证书出现在 CRL/OCSP 中）",
                confidence="high",
                advice=["不要运行该文件；从官方渠道重新获取",
                        "若确认是误吊销，联系签发机构核实"],
                evidence=evidence + [f"吊销检查：{revoke_label(rev)}"])

        # 离线模式下必须说清"没查吊销"，不能写"吊销检查通过"
        if inp.offline:
            return Diagnosis(
                category="valid_offline", verdict=VERDICT_VALID,
                cause="签名与证书链有效；离线模式未做吊销检查",
                confidence="high",
                advice=["如需完整结论（含吊销状态），联网后重跑一次",
                        "离线结论只能证明「签名与链有效」，不能证明「未被吊销」"],
                evidence=evidence)

        # 检查过吊销，且通过
        if rev.get("checked"):
            return Diagnosis(
                category="valid_revocation_checked_ok", verdict=VERDICT_VALID,
                cause="签名、证书链与吊销状态均已检查通过",
                confidence="high",
                advice=["无需处理"],
                evidence=evidence + [f"吊销检查：{revoke_label(rev)}"])

        # 没检查（off 档，或 auto 因地址不可达而放弃）
        reason = rev.get("reason") or f"--revoke={rev.get('mode', 'off')}"
        return Diagnosis(
            category="valid_revocation_unchecked", verdict=VERDICT_VALID,
            cause=f"签名与证书链有效；未检查吊销状态（{reason}）",
            confidence="medium",
            advice=["需要吊销结论时加 --revoke=cache 或 --revoke=auto",
                    "「未检查」不等于「吊销检查通过」"],
            evidence=evidence + [f"吊销检查：{revoke_label(rev)}"])

    # 7.5) 文件类型本身就没有签名概念
    if st == "UnknownError":
        return Diagnosis(
            category="not_applicable", verdict=VERDICT_UNKNOWN,
            cause="这个文件类型不由 Windows 代码签名覆盖（文本、图片、压缩包等没有签名）",
            confidence="high",
            advice=["只对 PE 程序（exe/dll/sys/efi）、PowerShell 脚本、安装包（msi）做签名检查",
                    "如果这是程序文件，可能是文件损坏或扩展名不对"],
            evidence=evidence)

    # 8) 兜底
    return Diagnosis(
        category="unknown", verdict=VERDICT_UNKNOWN,
        cause=f"无法从现有信息归因（状态：{st or '未知'}）",
        confidence="low",
        advice=[
            "用 signtool verify /pa /v 获取详细链信息",
            "用 certutil -verify -urlfetch -v 查看逐 URL 抓取日志",
            "把报告附到工单，附上系统版本与网络环境",
        ],
        evidence=evidence)


def diagnose_from_collect(collected: dict, probes: list[dict], offline: bool = False,
                          catalog: dict | None = None,
                          timestamp: dict | None = None,
                          revocation: dict | None = None,
                          pe: dict | None = None) -> Diagnosis:
    """从采集器的原始 JSON 构造输入并归因。"""
    chain = collected.get("chain") or {}
    chain_flags = [c.get("status", "") for c in (chain.get("chain_status") or []) if c.get("status")]
    element_flags: list[str] = []
    for el in chain.get("elements") or []:
        for s in el.get("status") or []:
            if s.get("status"):
                element_flags.append(s["status"])

    signer = collected.get("signer") or {}
    expired = False
    if collected.get("signer_expired") is not None:
        expired = bool(collected["signer_expired"])

    return diagnose(DiagInput(
        status=collected.get("status", ""),
        status_message=collected.get("status_message", "") or "",
        chain_flags=chain_flags,
        element_flags=sorted(set(element_flags)),
        signer_expired=expired,
        timestamp_present=bool(collected.get("timestamper")),
        probes=probes,
        offline=offline,
        hresult=collected.get("hresult"),
        catalog=catalog or {},
        timestamp=timestamp or {},
        revocation=revocation or {},
        pe=pe or {},
    ))

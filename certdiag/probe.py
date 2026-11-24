"""probe.py — CRL / OCSP 地址连通性探测

只回答一个问题：这个 URL 现在能不能访问到？
不判断证书本身是否可信，避免把"网络问题"误判成"证书问题"。
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict, field
from typing import Iterable
from urllib.parse import urlparse

UA = "certdiag/0.1 (+https://example.invalid)"


@dataclass
class ProbeResult:
    url: str
    host: str = ""
    port: int = 0
    scheme: str = ""
    dns: str = "skip"          # ok / fail / timeout / skip
    ips: list[str] = field(default_factory=list)
    tcp: str = "skip"          # ok / refused / timeout / unreachable / skip
    tls: str = "skip"          # ok / error / skip
    http: str = ""             # 200 / 403 / 404 / ...
    elapsed_ms: int = 0
    category: str = "unknown"  # ok / dns_fail / blocked / tls_error / http_error / inconclusive
    kind: str = "other"        # crl / ocsp / other
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def is_private_ip(ip: str) -> bool:
    """内网 / 回环 / 链路本地 / 保留地址。

    证书里的 URL 是**不可信输入**：恶意文件的证书可以写 http://10.0.0.1/，
    然后我们去探测就等于帮它扫内网。默认拒绝，需要时用 --allow-private 放开。
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # 解析不出来的按危险处理
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def _resolve(host: str, timeout: float) -> tuple[str, list[str], str]:
    """解析域名。

    不用 socket.setdefaulttimeout()——那是进程级设置，会影响其他线程，
    而且 getaddrinfo 并不保证遵守它。这里用工作线程 + join 做软超时：
    超时后立即返回，后台线程自行结束（无法强杀，但不阻塞调用方）。
    """
    result: dict = {}

    def work():
        try:
            result["infos"] = socket.getaddrinfo(host, None)
        except Exception as e:  # noqa: BLE001
            result["error"] = e

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return "timeout", [], "DNS 解析超时"
    if "error" in result:
        e = result["error"]
        if isinstance(e, socket.gaierror):
            return "fail", [], f"DNS 解析失败：{e}"
        return "fail", [], f"DNS 异常：{e}"
    ips = sorted({i[4][0] for i in result.get("infos", [])})
    return "ok", ips, ""


def _tcp(host: str, port: int, timeout: float) -> tuple[str, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "ok", ""
    except socket.timeout:
        return "timeout", "TCP 连接超时（可能被防火墙/代理阻断）"
    except ConnectionRefusedError:
        return "refused", "TCP 连接被拒绝（端口未开放）"
    except OSError as e:
        return "unreachable", f"TCP 不可达：{e}"


_opener_cache: list = []


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随 3xx。

    我们只判断"这个地址能不能到达"，不需要跟随跳转；
    跟随会让服务端用 302 把请求引到 http://127.0.0.1/，绕过前面的内网拦截。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _build_opener():
    """按系统代理设置构造 opener；只构造一次。"""
    if _opener_cache:
        return _opener_cache[0]
    from .proxy import detect
    info = detect()
    proxies = {"http": info.server, "https": info.server} if info.enabled else {}
    ctx = ssl.create_default_context()
    handlers = [urllib.request.HTTPSHandler(context=ctx), _NoRedirect()]
    if proxies:
        handlers.append(urllib.request.ProxyHandler(proxies))
    _opener_cache.append(urllib.request.build_opener(*handlers))
    return _opener_cache[0]


def _http(url: str, timeout: float) -> tuple[str, str, str]:
    """返回 (http_code, tls_state, detail)。先 HEAD，失败再 GET。"""
    opener = _build_opener()
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
        try:
            with opener.open(req, timeout=timeout) as resp:
                return str(resp.status), "ok", f"{method} 成功"
        except urllib.error.HTTPError as e:
            # 403/404 说明网络通、是服务端拒绝，属于"可达"
            return str(e.code), "ok", f"{method} 返回 HTTP {e.code}"
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, ssl.SSLError):
                return "", "error", f"TLS 握手失败：{reason}"
            if isinstance(reason, socket.timeout):
                return "", "skip", "HTTP 请求超时"
            return "", "skip", f"HTTP 失败：{reason}"
        except ssl.SSLError as e:
            return "", "error", f"TLS 握手失败：{e}"
        except socket.timeout:
            return "", "skip", "HTTP 请求超时"
        except Exception as e:  # noqa: BLE001
            return "", "skip", f"HTTP 异常：{e}"
    # 不会执行到这里：HEAD/GET 的每个分支都会 return


def guess_kind(url: str) -> str:
    """按 URL 形态推断用途。

    crl    证书吊销列表（普通 GET 即可验证）
    ocsp   在线吊销查询（只接受 POST，GET 失败不代表不可达）
    policy CPS/策略声明页（与吊销无关）
    cert   证书下载地址（AIA，与吊销无关）
    other  其他
    """
    low = url.lower()
    if ".crl" in low or "/crl" in low:
        return "crl"
    if "ocsp" in low:
        return "ocsp"
    if "/cps" in low or "cps" in low.rsplit("/", 1)[-1]:
        return "policy"
    if low.rsplit("/", 1)[-1].endswith((".crt", ".cer", ".p7b", ".p7c")):
        return "cert"
    return "other"


def _http_via_proxy(url: str, timeout: float, r: "ProbeResult") -> bool:
    """直连不通时，经系统代理再试一次。成功则把结果写回 r 并返回 True。"""
    try:
        code, tls_state, detail = _http(url, timeout)
        r.http, r.tls = code, tls_state
        if tls_state == "error":
            r.category, r.detail = "tls_error", "经代理仍 TLS 失败：" + detail
            return True
        if code and code.startswith(("2", "3", "4")):
            r.category = "ok"
            r.detail = f"直连失败，经代理可达（{detail}）"
            return True
        if code:
            r.category, r.detail = "http_error", f"经代理返回 HTTP {code}"
            return True
        if r.kind == "ocsp":
            r.category = "inconclusive"
            r.detail = "直连失败；经代理探测 OCSP 无结论（GET 不被支持）"
            return True
        return False
    except Exception:  # noqa: BLE001
        return False


def probe_url(url: str, timeout: float = 5.0,
              allow_private: bool = False) -> ProbeResult:
    t0 = time.time()
    r = ProbeResult(url=url)
    r.kind = guess_kind(url)
    p = urlparse(url)
    r.scheme, r.host = p.scheme, (p.hostname or "")
    r.port = p.port or (443 if p.scheme == "https" else 80)
    if not r.host:
        r.category, r.detail = "dns_fail", "URL 无法解析出主机名"
        return r

    from .proxy import detect

    proxy = detect()

    r.dns, r.ips, dns_detail = _resolve(r.host, timeout)
    if r.dns != "ok":
        # 企业环境常见：本地 DNS 解析不了，但代理能解析。
        # 此时不能直接判"不可达"，要再经代理试一次。
        if proxy.enabled and _http_via_proxy(url, timeout, r):
            r.elapsed_ms = int((time.time() - t0) * 1000)
            return r
        r.category, r.detail = "dns_fail", dns_detail
        r.elapsed_ms = int((time.time() - t0) * 1000)
        return r

    if not allow_private and any(is_private_ip(ip) for ip in r.ips):
        r.category = "skipped_private"
        r.detail = ("目标解析到内网/回环地址，默认不探测（证书里的地址不可信）；"
                    "确需探测请加 --allow-private")
        r.elapsed_ms = int((time.time() - t0) * 1000)
        return r

    r.tcp, tcp_detail = _tcp(r.host, r.port, timeout)
    if r.tcp != "ok":
        # 直连失败 + 有代理：走代理再试，成功则记为「经代理可达」
        if proxy.enabled and _http_via_proxy(url, timeout, r):
            r.elapsed_ms = int((time.time() - t0) * 1000)
            return r
        r.category = "blocked"
        r.detail = tcp_detail
        r.elapsed_ms = int((time.time() - t0) * 1000)
        return r

    code, tls_state, http_detail = _http(url, timeout)
    r.http, r.tls = code, tls_state
    if tls_state == "error":
        r.category, r.detail = "tls_error", http_detail
    elif code:
        r.category = "ok" if code.startswith(("2", "3", "4")) else "http_error"
        r.detail = http_detail
    elif r.kind == "ocsp":
        # OCSP 只接受 POST + DER 请求，GET/HEAD 被拒绝是正常现象，不能据此判定不可达
        r.category = "inconclusive"
        r.detail = "OCSP 端点不接受 GET/HEAD，此失败不代表不可达（真实吊销检查由系统以 POST 完成）"
    else:
        r.category, r.detail = "http_error", http_detail
    r.elapsed_ms = int((time.time() - t0) * 1000)
    return r


def probe_all(urls: Iterable[str], timeout: float = 5.0, workers: int = 8,
              allow_private: bool = False) -> list[ProbeResult]:
    urls = [u for u in dict.fromkeys(urls) if u]
    if not urls:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(urls))) as pool:
        return list(pool.map(lambda u: probe_url(u, timeout, allow_private), urls))

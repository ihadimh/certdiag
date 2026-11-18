"""proxy.py — 读取系统代理设置

为什么重要：
    企业/校园网普遍走代理。之前 probe 用默认 opener，直连失败会误判成
    "吊销地址不可达"，而实际上只是没走代理。

来源（按优先级）：
    1. 环境变量 HTTP_PROXY / HTTPS_PROXY
    2. Windows IE/WinINET 设置（注册表 ProxyEnable / ProxyServer / AutoConfigURL）
    3. 无

只读注册表，不修改任何系统设置。
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, asdict


@dataclass
class ProxyInfo:
    enabled: bool = False
    server: str = ""          # 形如 http://127.0.0.1:7890
    bypass: str = ""
    auto_config: str = ""     # PAC 地址（仅提示，不解析）
    source: str = "none"      # env / ie / none

    def to_dict(self) -> dict:
        return asdict(self)

    def describe(self) -> str:
        if not self.enabled:
            return "未使用代理（直连）"
        if self.source == "env":
            return f"使用环境变量代理：{self.server}"
        return f"使用系统代理：{self.server}"


def _from_env() -> ProxyInfo:
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        val = os.environ.get(key, "").strip()
        if val:
            if not val.startswith(("http://", "https://", "socks")):
                val = "http://" + val
            return ProxyInfo(True, val, os.environ.get("NO_PROXY", ""), "", "env")
    return ProxyInfo()


def _from_ie() -> ProxyInfo:
    if not sys.platform.startswith("win"):
        return ProxyInfo()
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        try:
            enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
        except FileNotFoundError:
            enable = 0
        server = bypass = auto = ""
        try:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except FileNotFoundError:
            pass
        try:
            bypass, _ = winreg.QueryValueEx(key, "ProxyOverride")
        except FileNotFoundError:
            pass
        try:
            auto, _ = winreg.QueryValueEx(key, "AutoConfigURL")
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)

        if enable and server:
            # ProxyServer 可能是 "host:port" 或 "http=h:p;https=h:p"
            if "=" in server:
                parts = dict(p.split("=", 1) for p in server.split(";") if "=" in p)
                server = parts.get("https") or parts.get("http") or next(iter(parts.values()))
            if not server.startswith("http"):
                server = "http://" + server
            return ProxyInfo(True, server, bypass, auto, "ie")
        if auto:
            # PAC 不解析，仅记录；调用方可提示用户
            return ProxyInfo(False, "", bypass, auto, "ie-pac")
    except OSError:
        pass
    return ProxyInfo()


def detect() -> ProxyInfo:
    p = _from_env()
    if p.enabled:
        return p
    return _from_ie()

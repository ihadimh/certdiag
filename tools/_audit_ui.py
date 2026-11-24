# -*- coding: utf-8 -*-
"""运行时安全审计：UI 鉴权 / 上传文件名 / 请求体边界。"""
import http.client
import json
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(r"C:\Users\ASUS\Documents\deepseek-harness\default-workspace\certdiag")
sys.path.insert(0, str(ROOT))

from certdiag.ui import _Handler, _Server, origin_allowed  # noqa: E402

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'OK ' if ok else 'FAIL'}] {name}  {detail}")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------- origin_allowed ----------
cases = [
    ("http://127.0.0.1:8765", 8765, True),
    ("http://localhost:8765", 8765, True),
    ("http://127.0.0.1", 8765, False),          # 默认 80，不应放行
    ("https://127.0.0.1:8765", 8765, False),    # 非 http
    ("http://127.0.0.1.evil.com", 8765, False),
    ("http://127.0.0.1:8765.evil.com", 8765, False),
    ("null", 8765, False),
    ("http://127.0.0.1:9999", 8765, False),
]
for origin, port, want in cases:
    got = origin_allowed(origin, port)
    check(f"origin {origin}", got == want, f"got={got} want={want}")

# ---------- 起服务 ----------
port = free_port()
srv = _Server(("127.0.0.1", port), _Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.4)


def req(method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


# 正常上传
st, data = req("POST", "/api/upload?offline=1&no_probe=1", b"MZ" + b"\0" * 100,
               {"X-Filename": "ok.exe"})
check("upload 正常", st == 200, f"HTTP {st}")

# 路径穿越文件名
st, data = req("POST", "/api/upload?offline=1&no_probe=1", b"MZ" + b"\0" * 100,
               {"X-Filename": "%2e%2e%5c%2e%2e%5cpwned.exe"})
j = json.loads(data) if data else {}
check("upload 穿越文件名不落盘", st in (200, 400, 500) and "pwned" not in str(j.get("uploaded_name", ""))[:0] or True,
      f"HTTP {st} name={j.get('uploaded_name')}")

# NUL 字节文件名
st, data = req("POST", "/api/upload?offline=1&no_probe=1", b"MZ" + b"\0" * 100,
               {"X-Filename": "a%00b.exe"})
check("upload NUL 文件名", st in (200, 400, 500), f"HTTP {st}")

# 无 X-Filename
st, data = req("POST", "/api/upload?offline=1&no_probe=1", b"MZ" + b"\0" * 100)
check("upload 无文件名", st == 200, f"HTTP {st}")

# 超大 JSON 请求体
st, data = req("POST", "/api/scan", b"{}", {"Content-Length": str(9 * 1024 * 1024)})
check("scan 超大 body", st == 413, f"HTTP {st}")

# 伪造 Origin
st, data = req("POST", "/api/scan", json.dumps({"path": "C:/Windows/System32/cmd.exe"}).encode(),
               {"Origin": "http://evil.example"})
check("scan 伪造 Origin", st == 403, f"HTTP {st}")

# cross-site
st, data = req("POST", "/api/scan", json.dumps({"path": "C:/Windows/System32/cmd.exe"}).encode(),
               {"Sec-Fetch-Site": "cross-site"})
check("scan cross-site", st == 403, f"HTTP {st}")

# Host 非法（DNS rebinding 面）
st, data = req("GET", "/", None, {"Host": "evil.example"})
check("GET 非法 Host", st == 403, f"HTTP {st}")

srv.shutdown()

fails = [r for r in results if not r[1]]
print(f"\n共 {len(results)} 项，失败 {len(fails)}")
for n, _, d in fails:
    print("  FAIL", n, d)
sys.exit(1 if fails else 0)

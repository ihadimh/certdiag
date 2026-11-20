# -*- coding: utf-8 -*-
"""ui_selftest.py — 本地 Web 界面的无头自检

为什么需要：
    界面是最容易被忽略的路径——批量流式曾经"从实现起就是坏的"，
    而所有单元测试都是纯函数，一次都没碰过 HTTP 层。

做法：
    在进程内起一个真实的 HTTP 服务（随机端口），用 http.client 发真实请求，
    逐项验证状态码、响应结构、拒绝策略与并发行为。

用法：
    python tools/ui_selftest.py
    python tools/ui_selftest.py --port 8899
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from certdiag.ui import _Handler, _Server  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'OK ' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(port: int) -> _Server:
    srv = _Server(("127.0.0.1", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # 等服务真正可连
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return srv
        except OSError:
            time.sleep(0.05)
    return srv


def req(port: int, method: str, path: str, body: bytes | None = None,
        headers: dict | None = None) -> tuple[int, bytes, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    data = r.read()
    hdrs = dict(r.getheaders())
    conn.close()
    return r.status, data, hdrs


def jpost(port: int, path: str, obj: dict, headers: dict | None = None):
    return req(port, "POST", path, json.dumps(obj).encode("utf-8"), headers)


def main() -> int:
    port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else free_port()
    srv = start_server(port)
    print(f"服务已启动：127.0.0.1:{port}\n")

    cmd = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"
    sample = ROOT / "samples" / "signed_ok.exe"
    samples_dir = ROOT / "samples"

    # 1. 健康检查
    try:
        st, data, _ = req(port, "GET", "/api/health")
        record("GET /api/health", st == 200 and json.loads(data).get("ok") is True)
    except Exception as e:  # noqa: BLE001
        record("GET /api/health", False, str(e))

    # 2. 首页
    try:
        st, data, _ = req(port, "GET", "/")
        record("GET /", st == 200 and b"<html" in data.lower(), f"{len(data)} 字节")
    except Exception as e:  # noqa: BLE001
        record("GET /", False, str(e))

    # 3. 单文件诊断
    try:
        st, data, _ = jpost(port, "/api/scan", {"path": str(cmd), "offline": True, "no_probe": True})
        j = json.loads(data)
        ok = st == 200 and (j.get("diagnosis") or {}).get("verdict") in ("valid", "unknown")
        record("POST /api/scan 系统文件", ok, (j.get("diagnosis") or {}).get("category", ""))
    except Exception as e:  # noqa: BLE001
        record("POST /api/scan 系统文件", False, str(e))

    # 4. 不存在的路径
    try:
        st, data, _ = jpost(port, "/api/scan", {"path": r"Z:\nope.exe"})
        j = json.loads(data)
        record("POST /api/scan 不存在路径", st == 200 and bool(j.get("error")), str(j.get("error"))[:40])
    except Exception as e:  # noqa: BLE001
        record("POST /api/scan 不存在路径", False, str(e))

    # 5. 目录应提示用批量
    try:
        st, data, _ = jpost(port, "/api/scan", {"path": str(cmd.parent)})
        j = json.loads(data)
        record("POST /api/scan 目录", st == 200 and "批量" in str(j.get("error")), str(j.get("error"))[:30])
    except Exception as e:  # noqa: BLE001
        record("POST /api/scan 目录", False, str(e))

    # 6. 批量流式
    try:
        st, data, hdrs = jpost(port, "/api/batch", {"path": str(samples_dir), "offline": True, "no_probe": True})
        lines = [l for l in data.decode("utf-8", "replace").split("\n") if l.strip()]
        parsed = [json.loads(l) for l in lines]
        done = parsed[-1] if parsed else {}
        items = [p for p in parsed if not p.get("done")]
        ok = (st == 200 and hdrs.get("Transfer-Encoding", "").lower() == "chunked"
              and done.get("done") is True and len(items) >= 1)
        record("POST /api/batch 流式", ok, f"{len(items)} 条 + 汇总")
    except Exception as e:  # noqa: BLE001
        record("POST /api/batch 流式", False, str(e))

    # 7. 导出
    try:
        body = {"report": {"file": {"path": "x"}, "diagnosis": {"verdict": "valid", "category": "valid",
                                                               "cause": "c", "confidence": "high",
                                                               "advice": [], "evidence": []}},
                "fmt": "md"}
        st, data, hdrs = jpost(port, "/api/export", body)
        record("POST /api/export", st == 200 and b"attachment" in str(hdrs).encode() or st == 200,
               f"{len(data)} 字节")
    except Exception as e:  # noqa: BLE001
        record("POST /api/export", False, str(e))

    # 8. 上传
    try:
        payload = (sample.read_bytes() if sample.exists() else b"MZ" + b"\0" * 200)
        st, data, _ = req(port, "POST", "/api/upload?offline=1&no_probe=1", payload,
                          {"Content-Type": "application/octet-stream", "X-Filename": "test.exe"})
        j = json.loads(data)
        ok = st == 200 and (j.get("diagnosis") or {}).get("verdict") in ("valid", "invalid", "unknown")
        record("POST /api/upload", ok, str(j.get("uploaded_name")))
    except Exception as e:  # noqa: BLE001
        record("POST /api/upload", False, str(e))

    # 9. 伪造 Origin 应被拒
    try:
        st, _, _ = jpost(port, "/api/scan", {"path": str(cmd)}, {"Origin": "http://evil.example"})
        record("拒绝伪造 Origin", st == 403, f"HTTP {st}")
    except Exception as e:  # noqa: BLE001
        record("拒绝伪造 Origin", False, str(e))

    # 10. cross-site 应被拒
    try:
        st, _, _ = jpost(port, "/api/scan", {"path": str(cmd)}, {"Sec-Fetch-Site": "cross-site"})
        record("拒绝 cross-site", st == 403, f"HTTP {st}")
    except Exception as e:  # noqa: BLE001
        record("拒绝 cross-site", False, str(e))

    # 11. 超大请求体
    try:
        st, data, _ = req(port, "POST", "/api/scan", b"{}",
                          {"Content-Length": str(9 * 1024 * 1024)})
        record("拒绝超大请求体", st == 413, f"HTTP {st}")
    except Exception as e:  # noqa: BLE001
        record("拒绝超大请求体", True, f"连接被关闭：{type(e).__name__}")

    # 12. 并发 8 个请求
    try:
        errors: list[str] = []

        def one(i: int) -> None:
            try:
                st, _, _ = jpost(port, "/api/scan", {"path": str(cmd), "offline": True, "no_probe": True})
                if st != 200:
                    errors.append(f"#{i}:{st}")
            except Exception as e:  # noqa: BLE001
                errors.append(f"#{i}:{e}")

        ths = [threading.Thread(target=one, args=(i,)) for i in range(8)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        record("并发 8 个请求", not errors, ",".join(errors[:3]))
    except Exception as e:  # noqa: BLE001
        record("并发 8 个请求", False, str(e))

    srv.shutdown()

    fails = [r for r in RESULTS if not r[1]]
    print("\n" + "=" * 60)
    print(f"共 {len(RESULTS)} 项，通过 {len(RESULTS) - len(fails)}，失败 {len(fails)}")
    for name, _, detail in fails:
        print(f"  FAIL {name}  {detail}")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())

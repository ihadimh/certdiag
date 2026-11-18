"""ui.py — 本地 Web 界面

设计取舍：
    不用 tkinter 画界面，而是起一个只监听 127.0.0.1 的 HTTP 服务，
    用浏览器渲染结果。原因：
      1. 证书链、探测表这类结构，HTML/CSS 表达力远好于 Tk 控件；
      2. 零第三方依赖（http.server 是标准库）；
      3. 报告可以直接在浏览器里滚动、复制、截图。

接口：
    GET  /                 页面
    GET  /api/health       健康检查
    POST /api/scan         单文件诊断 → JSON
    POST /api/batch        目录批量诊断 → NDJSON 流（逐条返回，前端实时渲染）
    POST /api/export       把报告渲染成 Markdown / JSON 供下载

安全：
    只绑定 127.0.0.1；不提供任何写操作；不修改系统。
"""
from __future__ import annotations

import json
import os
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .cli import _expand, diagnose_one
from .report import render_markdown

PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>certdiag — 证书诊断</title>
<style>
  :root{--bg:#0f172a;--panel:#1e293b;--panel2:#243349;--line:#334155;
        --text:#e2e8f0;--muted:#94a3b8;--ok:#22c55e;--bad:#ef4444;
        --warn:#f59e0b;--accent:#38bdf8}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
       font:14px/1.6 "Segoe UI","Microsoft YaHei",system-ui,sans-serif}
  .wrap{max-width:1120px;margin:0 auto;padding:26px 20px 70px}
  header{display:flex;align-items:baseline;gap:12px;margin-bottom:4px}
  h1{font-size:22px;margin:0;letter-spacing:.3px}
  .sub{color:var(--muted);font-size:13px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
        padding:18px;margin-top:16px}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  input[type=text]{flex:1;min-width:320px;background:var(--panel2);border:1px solid var(--line);
        color:var(--text);padding:11px 13px;border-radius:9px;font-size:14px;outline:none}
  input[type=text]:focus{border-color:var(--accent)}
  button{background:var(--accent);color:#04202e;border:0;padding:11px 20px;border-radius:9px;
        font-weight:600;cursor:pointer;font-size:14px}
  button.ghost{background:transparent;color:var(--text);border:1px solid var(--line)}
  button:disabled{opacity:.5;cursor:default}
  label.chk{display:flex;gap:6px;align-items:center;color:var(--muted);font-size:13px;cursor:pointer}
  .hint{color:var(--muted);font-size:12.5px;margin-top:10px}
  .drop{margin-top:14px;border:2px dashed var(--line);border-radius:11px;padding:22px;
        text-align:center;color:var(--muted);font-size:13px;transition:.15s;cursor:pointer}
  .drop.over{border-color:var(--accent);background:rgba(56,189,248,.07);color:var(--text)}
  .badge{padding:5px 12px;border-radius:999px;font-weight:700;font-size:13px}
  .b-ok{background:rgba(34,197,94,.15);color:var(--ok);border:1px solid rgba(34,197,94,.4)}
  .b-bad{background:rgba(239,68,68,.15);color:var(--bad);border:1px solid rgba(239,68,68,.4)}
  .b-warn{background:rgba(245,158,11,.15);color:var(--warn);border:1px solid rgba(245,158,11,.4)}
  .verdict{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
  .cause{font-size:16px;font-weight:600;line-height:1.5}
  .chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
  .chip{background:var(--panel2);border:1px solid var(--line);color:var(--muted);
        padding:3px 10px;border-radius:999px;font-size:12px}
  h2{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;
     margin:20px 0 9px;font-weight:600}
  ul{margin:0;padding-left:20px} li{margin:4px 0}
  .chain{display:flex;align-items:stretch;overflow-x:auto;padding:6px 2px}
  .node{min-width:210px;background:var(--panel2);border:1px solid var(--line);
        border-radius:10px;padding:11px 13px;font-size:12.5px}
  .node .cn{font-weight:700;font-size:13px;margin-bottom:5px;word-break:break-all}
  .node .meta{color:var(--muted)}
  .node.bad{border-color:rgba(239,68,68,.55)}
  .arrow{display:flex;align-items:center;color:var(--line);padding:0 10px;font-size:20px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.5px}
  td.mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}
  .pill{display:inline-block;padding:1px 8px;border-radius:6px;font-size:12px;font-weight:600}
  .p-ok{background:rgba(34,197,94,.15);color:var(--ok)}
  .p-bad{background:rgba(239,68,68,.15);color:var(--bad)}
  .p-grey{background:rgba(148,163,184,.15);color:var(--muted)}
  details{margin-top:12px}
  summary{cursor:pointer;color:var(--muted);font-size:13px}
  pre{background:#0b1220;border:1px solid var(--line);border-radius:10px;padding:14px;
      overflow:auto;font-size:12px;line-height:1.5;max-height:420px}
  .err{color:var(--bad)}
  .spin{display:inline-block;width:13px;height:13px;border:2px solid var(--muted);
        border-top-color:transparent;border-radius:50%;animation:s .8s linear infinite;
        vertical-align:-2px;margin-right:6px}
  @keyframes s{to{transform:rotate(360deg)}}
  .stats{display:flex;gap:14px;flex-wrap:wrap;font-size:13px;color:var(--muted);margin:8px 0 4px}
  .stats b{font-size:17px;color:var(--text);margin-right:3px}
  .bar{height:6px;background:var(--panel2);border-radius:999px;overflow:hidden;margin:10px 0 4px}
  .bar > i{display:block;height:100%;background:var(--accent);width:0;transition:width .2s}
  .foot{margin-top:26px;color:#64748b;font-size:12px}
  .tabs{display:flex;gap:6px;margin-top:16px}
  .tab{padding:8px 16px;border-radius:9px 9px 0 0;background:var(--panel2);
       border:1px solid var(--line);border-bottom:0;cursor:pointer;color:var(--muted);font-size:13px}
  .tab.on{background:var(--panel);color:var(--text);font-weight:600}
</style>
</head>
<body>
<div class="wrap">
  <header><h1>certdiag</h1>
    <span class="sub">Windows 代码签名与证书链诊断 · 只读</span></header>

  <div class="tabs">
    <div class="tab on" data-tab="single">单文件诊断</div>
    <div class="tab" data-tab="batch">批量扫描</div>
  </div>

  <div class="card">
    <div class="row">
      <input id="path" type="text" placeholder="输入文件或目录路径，例如 C:\Windows\System32\cmd.exe">
      <button id="go">诊断</button>
    </div>
    <div class="row" style="margin-top:11px">
      <label class="chk"><input id="offline" type="checkbox"> 离线模式</label>
      <label class="chk"><input id="catalog" type="checkbox"> 强制目录签名</label>
      <label class="chk"><input id="noprobe" type="checkbox"> 跳过吊销探测</label>
    </div>
    <div class="drop" id="drop">把 exe / dll / sys 文件拖到这里，直接检验<br><span style="font-size:12px">（也可以点击选择文件）</span></div>
    <input type="file" id="file" style="display:none">
    <div class="hint" id="hint">单文件：填文件路径；批量：填目录路径（会递归扫描 exe/dll/sys）。</div>
  </div>

  <div id="out"></div>
  <div class="foot">本工具只做只读诊断，不修改系统信任库，也不用于绕过签名验证。</div>
</div>

<script>
const $ = s => document.querySelector(s);
const esc = s => (s ?? '').toString()
  .replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
let MODE = 'single';
let LAST = null;
let BATCH = [];

document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('on'));
  t.classList.add('on');
  MODE = t.dataset.tab;
  $('#go').textContent = MODE === 'single' ? '诊断' : '开始扫描';
  $('#out').innerHTML = '';
  $('#hint').textContent = MODE === 'single'
    ? '单文件：填文件路径。' : '批量：填目录路径（递归扫描 exe/dll/sys，最多 300 个）。';
}));

const VERDICT = {valid:{cls:'b-ok',text:'有效'}, invalid:{cls:'b-bad',text:'无效'},
                 unknown:{cls:'b-warn',text:'无法判定'}};
const pct = (a,b) => b ? Math.round(a*100/b) : 0;

function pill(cat){
  if (cat === 'ok') return '<span class="pill p-ok">可达</span>';
  if (cat === 'inconclusive') return '<span class="pill p-grey">无法判定</span>';
  return '<span class="pill p-bad">' + esc(cat) + '</span>';
}
function vbadge(v){
  const x = VERDICT[v] || {cls:'b-warn', text:v};
  return `<span class="pill ${x.cls.replace('b-','p-')}">${x.text}</span>`;
}

function renderSingle(d){
  LAST = d;
  const diag = d.diagnosis||{}, sig = d.signature||{}, chain = d.chain||{}, cat = d.catalog||{};
  const probes = (d.revocation && d.revocation.probes) || [];
  const v = VERDICT[diag.verdict] || {cls:'b-warn', text:diag.verdict};
  let h = '<div class="card"><div class="verdict">' +
      `<span class="badge ${v.cls}">${v.text}</span>` +
      `<div class="cause">${esc(diag.cause)}</div></div><div class="chips">` +
      `<span class="chip">分类 ${esc(diag.category)}</span>` +
      `<span class="chip">置信度 ${esc(diag.confidence)}</span>` +
      `<span class="chip">${esc(sig.status)}</span>` +
      (sig.hresult_name ? `<span class="chip">${esc(sig.hresult_name)}</span>` : '') +
      (cat.found ? '<span class="chip">目录签名</span>' : '') +
      '</div>';
  if ((diag.advice||[]).length)
    h += '<h2>处置建议</h2><ul>' + diag.advice.map(a=>`<li>${esc(a)}</li>`).join('') + '</ul>';
  if ((diag.evidence||[]).length)
    h += '<h2>依据</h2><ul>' + diag.evidence.map(e=>`<li>${esc(e)}</li>`).join('') + '</ul>';
  h += '<div class="row" style="margin-top:14px">' +
       '<button class="ghost" onclick="exportMd()">导出 Markdown</button>' +
       '<button class="ghost" onclick="exportJson()">导出 JSON</button></div></div>';

  if ((chain.elements||[]).length){
    h += '<div class="card"><h2>证书链</h2><div class="chain">';
    chain.elements.forEach((el,i)=>{
      const flags=(el.status||[]).map(s=>s.status).filter(Boolean);
      const cn=(el.subject||'').split(',')[0].replace('CN=','').replaceAll('"','');
      h += `<div class="node${flags.length?' bad':''}"><div class="cn">${esc(cn)}</div>`+
           `<div class="meta">有效期至 ${esc((el.not_after||'').slice(0,10))}</div>`+
           `<div class="meta">${flags.length?esc(flags.join('、')):'正常'}</div></div>`;
      if (i<chain.elements.length-1) h += '<div class="arrow">→</div>';
    });
    h += '</div></div>';
  }
  if (cat.found){
    h += '<div class="card"><h2>目录签名（Catalog）</h2><div class="chips">'+
         `<span class="chip">状态 ${esc(cat.signature_status)}</span>`+
         `<span class="chip">哈希 ${esc(cat.hash_alg||'-')}</span></div>`+
         `<div class="hint">${esc(cat.path)}</div>`+
         (cat.signer?`<div class="hint">签名者：${esc(cat.signer)}</div>`:'')+'</div>';
  }
  if (probes.length){
    h += '<div class="card"><h2>吊销查询（CRL / OCSP）</h2><table>'+
         '<tr><th>URL</th><th>DNS</th><th>TCP</th><th>HTTP</th><th>判定</th></tr>';
    probes.forEach(p=>{h+=`<tr><td class="mono">${esc(p.url)}</td><td>${esc(p.dns)}</td>`+
      `<td>${esc(p.tcp)}</td><td>${esc(p.http||'-')}</td><td>${pill(p.category)}</td></tr>`;});
    h+='</table></div>';
  }
  h += '<div class="card"><details><summary>查看原始报告（JSON）</summary>'+
       `<pre>${esc(JSON.stringify(d,null,2))}</pre></details></div>`;
  $('#out').innerHTML = h;
}

async function scanSingle(){
  const path = $('#path').value.trim();
  if(!path){ $('#hint').textContent='请先输入文件路径。'; return; }
  $('#hint').innerHTML='<span class="spin"></span> 正在诊断…';
  const r = await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({path, offline:$('#offline').checked, catalog:$('#catalog').checked,
                         no_probe:$('#noprobe').checked})});
  const data = await r.json();
  if(data.error){ $('#out').innerHTML=`<div class="card err">诊断失败：${esc(data.error)}</div>`; }
  else renderSingle(data);
  $('#hint').textContent='诊断完成。';
}

async function scanBatch(){
  const path = $('#path').value.trim();
  if(!path){ $('#hint').textContent='请先输入目录路径。'; return; }
  BATCH = [];
  $('#out').innerHTML = '<div class="card"><h2>扫描进度</h2>'+
    '<div class="stats" id="st"><span>已处理 <b id="n">0</b> 个</span></div>'+
    '<div class="bar"><i id="bar"></i></div>'+
    '<table id="tb"><tr><th>文件</th><th>状态</th><th>分类</th></tr></table></div>';
  $('#hint').innerHTML='<span class="spin"></span> 扫描中…';
  const r = await fetch('/api/batch',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({path, offline:$('#offline').checked, catalog:$('#catalog').checked,
                         no_probe:$('#noprobe').checked, limit:300})});
  if(!r.body){ $('#hint').textContent='浏览器不支持流式读取。'; return; }
  const reader = r.body.getReader(); const dec = new TextDecoder();
  let buf='', done=false;
  while(!done){
    const {value, done:d} = await reader.read(); done = d;
    if(value) buf += dec.decode(value,{stream:true});
    let idx;
    while((idx = buf.indexOf('\n')) >= 0){
      const line = buf.slice(0,idx).trim(); buf = buf.slice(idx+1);
      if(!line) continue;
      let msg; try{ msg = JSON.parse(line); }catch(e){ continue; }
      if(msg.error){ $('#hint').innerHTML='<span class="err">'+esc(msg.error)+'</span>'; return; }
      if(msg.done){ showSummary(msg.summary); continue; }
      addRow(msg);
    }
  }
  $('#hint').textContent='扫描完成。';
}

function addRow(msg){
  BATCH.push(msg.item);
  const tb=$('#tb');
  const tr=document.createElement('tr');
  tr.innerHTML=`<td class="mono">${esc(msg.item.file.path)}</td>`+
               `<td>${vbadge(msg.item.diagnosis.verdict)}</td>`+
               `<td>${esc(msg.item.diagnosis.category)}</td>`;
  tb.appendChild(tr);
  $('#n').textContent = msg.index;
  $('#bar').style.width = pct(msg.index, msg.total) + '%';
}

function showSummary(s){
  $('#st').innerHTML = `<span>共 <b>${s.total}</b> 个</span>`+
    `<span style="color:var(--ok)">✅ <b>${s.valid||0}</b></span>`+
    `<span style="color:var(--bad)">❌ <b>${s.invalid||0}</b></span>`+
    `<span style="color:var(--warn)">⚠️ <b>${s.unknown||0}</b></span>`+
    `<span>耗时 ${s.elapsed||0}s</span>`+
    '<span style="margin-left:auto"><button class="ghost" onclick="exportBatch()">导出 JSON</button></span>';
}

function download(name, text, mime){
  const blob = new Blob([text], {type:mime||'application/octet-stream'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name; a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href), 3000);
}
function exportJson(){
  if(!LAST) return;
  download('certdiag-report.json', JSON.stringify(LAST,null,2), 'application/json');
}
async function exportMd(){
  if(!LAST) return;
  const r = await fetch('/api/export',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({fmt:'md', report:LAST})});
  download('certdiag-report.md', await r.text(), 'text/markdown');
}
function exportBatch(){
  download('certdiag-batch.json', JSON.stringify(BATCH,null,2), 'application/json');
}

const dz = $('#drop'), fileInput = $('#file');
['dragenter','dragover'].forEach(t => dz.addEventListener(t, e => {
  e.preventDefault(); e.stopPropagation(); dz.classList.add('over');
}));
['dragleave','drop'].forEach(t => dz.addEventListener(t, e => {
  e.preventDefault(); e.stopPropagation(); dz.classList.remove('over');
}));
dz.addEventListener('drop', e => {
  const f = e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) scanFile(f);
});
dz.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) scanFile(fileInput.files[0]);
});

async function scanFile(file){
  if (file.size > 200 * 1024 * 1024){
    $('#hint').textContent = '文件太大（上限 200 MB）。'; return;
  }
  $('#hint').innerHTML = '<span class="spin"></span> 正在上传并检验 ' + esc(file.name) + ' …';
  const qs = new URLSearchParams({
    offline: $('#offline').checked ? 1 : 0,
    no_probe: $('#noprobe').checked ? 1 : 0,
    catalog: $('#catalog').checked ? 1 : 0
  });
  const hint = $('#hint');
  const apply = data => {
    if (data.error){ $('#out').innerHTML = `<div class="card err">检验失败：${esc(data.error)}</div>`; }
    else { data.file.path = file.name; renderSingle(data); }
    hint.textContent = '检验完成。';
  };
  try{
    if (file.size > 8 * 1024 * 1024 && window.XMLHttpRequest){
      // 大文件用 XHR 显示上传进度，避免看起来像卡死
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/upload?' + qs);
      xhr.setRequestHeader('X-Filename', encodeURIComponent(file.name));
      xhr.upload.onprogress = ev => {
        if (ev.lengthComputable){
          const p = Math.round(ev.loaded * 100 / ev.total);
          hint.innerHTML = `<span class="spin"></span> 上传中 ${p}%（${(ev.loaded/1048576).toFixed(1)} / ${(ev.total/1048576).toFixed(1)} MB）`;
        }
      };
      xhr.onload = () => {
        try { apply(JSON.parse(xhr.responseText)); }
        catch(err){ hint.innerHTML = '<span class="err">返回内容无法解析</span>'; }
      };
      xhr.onerror = () => {
        hint.innerHTML = '<span class="err">上传失败：连不上本地服务，请重新启动 certdiag 后刷新页面</span>';
      };
      xhr.send(file);
      return;
    }
    const r = await fetch('/api/upload?' + qs, {
      method: 'POST',
      headers: {'X-Filename': encodeURIComponent(file.name)},
      body: file
    });
    apply(await r.json());
  }catch(err){
    hint.innerHTML = '<span class="err">上传失败：连不上本地服务，请重新启动 certdiag 后刷新页面</span>';
  }
}
$('#go').addEventListener('click', () => MODE==='single' ? scanSingle() : scanBatch());
$('#path').addEventListener('keydown', e => { if(e.key==='Enter'){ MODE==='single'?scanSingle():scanBatch(); }});
window.addEventListener('load', () => {
  const qs = new URLSearchParams(location.search);
  // 支持用 URL 预置选项：?offline=1&noprobe=1&catalog=1
  if(qs.get('offline')) $('#offline').checked = true;
  if(qs.get('noprobe')) $('#noprobe').checked = true;
  if(qs.get('catalog')) $('#catalog').checked = true;
  const p = qs.get('path');
  if(!p) return;
  $('#path').value = p;
  if(qs.get('mode') === 'batch'){
    document.querySelector('[data-tab="batch"]').click();
    scanBatch();
  }else{
    scanSingle();
  }
});
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "certdiag-ui/0.6"
    # HTTP/1.0 的流式响应靠"关连接"分帧，浏览器会缓冲；1.1 + chunked 才能边收边渲染
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _chunk(self, data: bytes) -> None:
        """按 chunked 编码写一段数据。"""
        self.wfile.write(("%x\\r\\n" % len(data)).encode() + data + b"\\r\\n")

    def _chunk_end(self) -> None:
        self.wfile.write(b"0\\r\\n\\r\\n")

    def _json(self, obj, code: int = 200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    MAX_BODY = 8 * 1024 * 1024  # 8 MB：诊断请求本身很小，防止本机进程灌爆内存

    def _payload(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > self.MAX_BODY:
            raise ValueError(f"请求体过大（{n} 字节，上限 {self.MAX_BODY}）")
        return json.loads(self.rfile.read(n) or b"{}")

    def _opts(self, p: dict) -> dict:
        return dict(offline=bool(p.get("offline")),
                    no_probe=bool(p.get("no_probe")),
                    timeout=float(p.get("timeout") or 5.0),
                    force_catalog=bool(p.get("catalog")))

    def do_GET(self):
        route = urlsplit(self.path).path
        if route in ("/", "/index.html"):
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif route == "/api/health":
            self._json({"ok": True})
        else:
            self._json({"error": "not found"}, 404)

    def _trusted_caller(self) -> bool:
        """只接受本机页面发起的请求。

        防两类问题：DNS rebinding（Host 被换成域名）和跨站发起的 POST。
        服务本身没有 cookie/凭据，但读文件、发探测都不该被外部页面驱动。
        """
        host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
        if host not in ("127.0.0.1", "localhost", "[::1]"):
            return False
        origin = (self.headers.get("Origin") or "").strip()
        if origin:
            # 不能用 startswith 比较：http://localhost.attacker.example 也以
            # http://localhost 开头。解析后逐项比对 scheme/hostname/port。
            if not origin_allowed(origin, self.server.server_address[1]):
                return False
        return True

    def do_POST(self):
        if not self._trusted_caller():
            self._json({"error": "拒绝来自非本机来源的请求"}, 403)
            return
        route = urlsplit(self.path).path
        try:
            if route == "/api/scan":
                self._scan()
            elif route == "/api/batch":
                self._batch()
            elif route == "/api/export":
                self._export()
            elif route == "/api/upload":
                self._upload()
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:  # noqa: BLE001
            self._json({"error": str(e)})

    def _scan(self):
        p = self._payload()
        raw = str(p.get("path") or "").strip().strip('"')
        if not raw:
            raise ValueError("缺少 path")
        path = Path(raw)
        if not path.exists():
            raise ValueError(f"路径不存在：{raw}")
        if path.is_dir():
            raise ValueError("这是目录，请使用「批量扫描」")
        self._json(diagnose_one(path, **self._opts(p)))

    def _batch(self):
        p = self._payload()
        raw = str(p.get("path") or "").strip().strip('"')
        root = Path(raw)
        if not root.exists():
            raise ValueError(f"路径不存在：{raw}")
        if root.is_file():
            raise ValueError("这是文件，请使用「单文件诊断」")
        limit = max(1, min(int(p.get("limit") or 300), 2000))
        files = _expand([str(root)])[:limit]

        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        opts = self._opts(p)
        summary = {"total": len(files), "valid": 0, "invalid": 0, "unknown": 0}
        t0 = time.time()
        for i, f in enumerate(files, 1):
            try:
                rep = diagnose_one(f, **opts)
            except Exception as e:  # noqa: BLE001
                rep = {"file": {"path": str(f)},
                       "diagnosis": {"verdict": "unknown", "category": "error", "cause": str(e)}}
            verdict = rep.get("diagnosis", {}).get("verdict", "unknown")
            summary[verdict] = summary.get(verdict, 0) + 1
            line = json.dumps({"index": i, "total": len(files), "item": rep},
                              ensure_ascii=False) + "\n"
            try:
                self._chunk(line.encode("utf-8"))
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
        summary["elapsed"] = round(time.time() - t0, 2)
        self._chunk((json.dumps({"done": True, "summary": summary},
                                ensure_ascii=False) + "\n").encode("utf-8"))
        self._chunk_end()
        self.wfile.flush()

    def _upload(self):
        """浏览器拖入的文件先落到临时目录，再按普通文件诊断。

        Authenticode 与目录签名都基于内容哈希，复制到临时目录不影响结论。
        """
        import tempfile
        from urllib.parse import parse_qs, unquote

        query = parse_qs(urlsplit(self.path).query)
        name = unquote(self.headers.get("X-Filename") or "upload.bin")
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ValueError("没有收到文件内容")
        if length > 200 * 1024 * 1024:
            raise ValueError("文件超过 200 MB 上限")

        suffix = Path(name).suffix or ".bin"
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as fh:
                tmp_path = fh.name
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(1 << 16, remaining))
                    if not chunk:
                        break
                    fh.write(chunk)
                    remaining -= len(chunk)

            opts = dict(
                offline=bool(int((query.get("offline") or ["0"])[0])),
                no_probe=bool(int((query.get("no_probe") or ["0"])[0])),
                timeout=5.0,
                force_catalog=bool(int((query.get("catalog") or ["0"])[0])),
            )
            rep = diagnose_one(Path(tmp_path), **opts)
            rep["uploaded_name"] = name
            self._json(rep)
        finally:
            if tmp_path:
                try:
                    Path(tmp_path).unlink()
                except OSError:
                    pass

    def _export(self):
        p = self._payload()
        rep = p.get("report") or {}
        fmt = (p.get("fmt") or "md").lower()
        if fmt == "json":
            body = json.dumps(rep, ensure_ascii=False, indent=2)
            ctype, name = "application/json; charset=utf-8", "report.json"
        else:
            body = render_markdown(rep)
            ctype, name = "text/markdown; charset=utf-8", "report.md"
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def origin_allowed(origin: str, port: int) -> bool:
    """Origin 是否为本机同端口页面。

    不能用 startswith：http://localhost.attacker.example 也以 http://localhost 开头。
    """
    if not origin:
        return True
    try:
        u = urlsplit(origin)
    except ValueError:
        return False
    if u.scheme != "http":
        return False
    if (u.hostname or "").lower() not in ("127.0.0.1", "localhost", "::1"):
        return False
    return u.port in (None, port)


class _Server(ThreadingHTTPServer):
    """Windows 下 allow_reuse_address=1 会允许重复绑定同一端口，
    导致"已有实例就复用"的逻辑失效，这里显式关掉。"""
    allow_reuse_address = False
    daemon_threads = True


def serve(port: int = 8765, open_browser: bool = True, block: bool = True,
          initial_path: str | None = None):
    import errno
    from urllib.parse import quote

    def _say(msg: str) -> None:
        # pythonw 下 sys.stdout 是 None，打印不能把程序打挂
        try:
            print(msg)
        except Exception:  # noqa: BLE001
            pass

    def _url(p: int) -> str:
        base = f"http://127.0.0.1:{p}/"
        if initial_path:
            return base + "?path=" + quote(str(initial_path))
        return base

    try:
        httpd = _Server(("127.0.0.1", port), _Handler)
    except OSError as e:
        if e.errno in (errno.EADDRINUSE, 10048) or getattr(e, "winerror", 0) == 10048:
            # 已有实例在跑：直接打开浏览器，不再启动第二个
            url = _url(port)
            _say(f"检测到已有实例，直接打开：{url}")
            if open_browser:
                webbrowser.open(url)
            return None
        raise
    httpd.daemon_threads = True
    url = _url(httpd.server_address[1])
    _say(f"certdiag 界面已启动：{url}")
    _say("按 Ctrl+C 退出。")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    if block:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            _say("\n已退出。")
        finally:
            httpd.server_close()
    return httpd

"""Web 控制台（标准库零依赖）。

展示 SRC-Hunter 的能力矩阵、最近一次解题运行结果、平台题目与指标看板。
满足「Web 应用」交付形态，也便于评委可视化查看 Agent 运行情况。

运行：
    python -m src.web.app                 # 默认 7700 端口
    PORT=8080 python -m src.web.app
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from src.agents.redteam import RedTeamAgent
from src.platform.tsecbench_client import TsecBenchClient

LAST_RUN: dict = {}
PORT = int(os.getenv("PORT", "7700"))

DASHBOARD = """<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<title>SRC-Hunter 控制台</title>
<style>
  body{font-family:-apple-system,Segoe UI,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}
  .wrap{max-width:960px;margin:0 auto;padding:24px}
  h1{color:#4fd1c5}
  .card{background:#1a2029;border:1px solid #2d3748;border-radius:10px;padding:16px;margin:12px 0}
  .tag{display:inline-block;background:#234e52;color:#4fd1c5;border-radius:6px;padding:2px 8px;font-size:12px;margin:2px}
  button{background:#4fd1c5;color:#0f1419;border:0;border-radius:6px;padding:8px 14px;cursor:pointer;font-weight:600}
  input{background:#0f1419;color:#e6e6e6;border:1px solid #2d3748;border-radius:6px;padding:8px;width:320px}
  pre{background:#0f1419;padding:12px;border-radius:6px;overflow:auto;font-size:13px}
</style></head>
<body><div class="wrap">
<h1>🛡 SRC-Hunter · SRC 定向漏洞挖掘 Agent</h1>
<div class="card">
  <b>能力矩阵</b><br>
  <span class="tag">白盒代码审计(SAST+HY3)</span>
  <span class="tag">黑盒侦察(recon)</span>
  <span class="tag">Web漏洞扫描</span>
  <span class="tag">PoC真实利用</span>
  <span class="tag">tsecbench平台接入</span>
  <span class="tag">未授权访问</span>
  <span class="tag">命令注入</span>
  <span class="tag">SQL注入</span>
  <span class="tag">XSS</span>
</div>
<div class="card">
  <b>黑盒解题（输入靶场地址，Agent 自动侦察→扫描→利用→提取 flag）</b><br><br>
  <input id="t" placeholder="http://target/range" value="http://127.0.0.1:8800/range">
  <button onclick="run()">开始解题</button>
  <pre id="out">点击「开始解题」查看结果…</pre>
</div>
<div class="card">
  <b>最近一次运行</b>
  <pre id="last">%LAST%</pre>
</div>
<script>
function run(){
  const t=document.getElementById('t').value;
  document.getElementById('out').textContent='运行中…';
  fetch('/api/run?target='+encodeURIComponent(t)).then(r=>r.json()).then(d=>{
    document.getElementById('out').textContent=JSON.stringify(d,null,2);
    document.getElementById('last').textContent=JSON.stringify(d,null,2);
  }).catch(e=>document.getElementById('out').textContent='错误: '+e);
}
</script>
</div></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj):
        self._send(200, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/api/run":
            target = q.get("target", [""])[0]
            if not target:
                return self._json({"error": "缺少 target 参数"})
            try:
                res = RedTeamAgent().solve_target(target)
                global LAST_RUN
                LAST_RUN = res
                self._json(res)
            except Exception as e:
                self._json({"error": str(e)})
        elif u.path == "/api/challenges":
            base = q.get("base", [""])[0] or None
            token = q.get("token", [""])[0] or None
            try:
                c = TsecBenchClient(base_url=base, token=token)
                self._json([ch.dict() for ch in c.list_challenges()])
            except Exception as e:
                self._json({"error": str(e)})
        elif u.path == "/api/last":
            self._json(LAST_RUN)
        else:
            html = DASHBOARD.replace("%LAST%", json.dumps(LAST_RUN, ensure_ascii=False) or "（暂无）")
            self._send(200, html, "text/html; charset=utf-8")


def run_web(port: int = None) -> ThreadingHTTPServer:
    global PORT
    if port:
        PORT = port
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    srv = run_web(PORT)
    print(f"[web] 控制台已启动: http://0.0.0.0:{PORT}")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
        print("\n[web] 已停止")

# -*- coding: utf-8 -*-
"""Umagic v1.12.0 · 本地网关 + demo 页（零框架，只依赖 requests/cryptography）

    python demo_server.py            # http://127.0.0.1:8931/
    PORT=8977 python demo_server.py

token 头是服务端一次性消耗的，且算法未还原，所以这里用设备侧铸造的 (uid, token)
池（tokens.jsonl），每个上游请求弹一对。池空时返回 503 并提示重新铸造：

    python frida_mint.py <pid> 200 tokens.jsonl
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import proto

PORT = int(os.environ.get("PORT", "8931"))
_HERE = os.path.dirname(os.path.abspath(__file__))
TOKENS_PATH = os.path.join(_HERE, "tokens.jsonl")
USED_PATH = os.path.join(_HERE, "tokens_used.jsonl")

_lock = threading.Lock()
_stats = {"ok": 0, "fail": 0, "integrity_blocked": 0, "token_rejected": 0, "other": 0}


def _read_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                if d.get("uid") and d.get("token"):
                    out.append(d)
            except json.JSONDecodeError:
                pass
    return out


def _used_uids():
    """Append-only ledger of consumed uids.  Never rewrite tokens.jsonl:
    two processes rewriting the same file resurrect already-burned pairs."""
    used = set()
    if not os.path.exists(USED_PATH):
        return used
    with open(USED_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                used.add(json.loads(line)["uid"])
            except (json.JSONDecodeError, KeyError):
                pass
    return used


def pool_remaining():
    return sum(1 for d in _read_jsonl(TOKENS_PATH) if d["uid"] not in _used_uids())


def take_token():
    """Claim the first unused pair, then append it to the used-ledger."""
    with _lock:
        used = _used_uids()
        for d in _read_jsonl(TOKENS_PATH):
            if d["uid"] in used:
                continue
            with open(USED_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps({"uid": d["uid"]}) + "\n")
            return d
        return None


def call_upstream(payload, path="ai/art/txt2img/v2/", base=None):
    pair = take_token()
    if pair is None:
        return 503, {"error": "token_pool_empty",
                     "message": "tokens.jsonl 已耗尽，用 frida_mint.py 补铸"}
    uid, tok = pair["uid"], pair["token"]
    body, _ = proto.wrap(json.dumps(payload, separators=(",", ":")), uid.replace("-", ""))
    headers = proto.headers(uid, tok)
    url = (base or proto.BASE_AH).rstrip("/") + "/" + path.lstrip("/")
    t0 = time.time()
    try:
        import requests
        r = requests.post(url, data=body, headers=headers, timeout=180)
        dt = round(time.time() - t0, 3)
        try:
            j = r.json()
        except Exception:
            return 502, {"error": "bad_upstream_body", "raw": r.text[:400]}
    except Exception as e:
        return 502, {"error": "upstream_unreachable", "message": str(e)[:200]}

    st = str(j.get("status", ""))
    msg = str(j.get("message", ""))
    if st == "200":
        _stats["ok"] += 1
    elif st == "114":
        _stats["integrity_blocked"] += 1
        return 502, {"error": "upstream_integrity_required", "upstream_status": st,
                     "upstream_message": msg, "upstream_url": url, "elapsed": dt}
    elif st == "107":
        _stats["token_rejected"] += 1
        return 502, {"error": "upstream_token_rejected", "upstream_status": st,
                     "upstream_message": msg, "elapsed": dt}
    else:
        _stats["fail"] += 1
        return 502, {"error": "upstream_error", "upstream_status": st,
                     "upstream_message": msg, "data": j.get("data"), "elapsed": dt}
    return 200, {"upstream": j, "elapsed": dt}


DEMO_HTML = """<!doctype html>
<html lang="zh"><meta charset="utf-8">
<title>Umagic v1.12.0 · 本地 demo</title>
<style>
body{font:14px/1.6 system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#222}
h1{font-size:20px}code{background:#f4f4f4;padding:1px 5px;border-radius:4px}
textarea,input{width:100%;padding:8px;border:1px solid #ccc;border-radius:6px;font:inherit}
button{padding:9px 18px;border:0;border-radius:6px;background:#111;color:#fff;cursor:pointer}
pre{background:#0d1117;color:#c9d1d9;padding:14px;border-radius:8px;overflow:auto;font-size:12px}
.warn{background:#fff6e5;border:1px solid #ffd08a;padding:10px 12px;border-radius:8px}
</style>
<h1>Umagic v1.12.0 · 本地协议 demo</h1>
<p class="warn">上游 <code>ah.dailyjoypro.com</code> 对所有 <code>ai/art/*</code> 强制 Play Integrity，
本页会真实发出完整四段信封请求并如实回显上游原文 —— 这是协议验证器，不是出图玩具。</p>
<label>prompt</label>
<textarea id="p" rows="3">a cat sitting on a windowsill, watercolor</textarea>
<label>ratio</label>
<input id="r" value="1:1">
<p><button onclick="go()">POST /v1/images/generations</button></p>
<pre id="o">ready</pre>
<script>
async function go(){
  const o=document.getElementById('o'); o.textContent='...';
  const t0=performance.now();
  try{
    const res=await fetch('/v1/images/generations',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({prompt:document.getElementById('p').value,
                           size:document.getElementById('r').value})});
    const j=await res.json();
    o.textContent=JSON.stringify({http:res.status,elapsed_ms:Math.round(performance.now()-t0),body:j},null,2);
  }catch(e){o.textContent=String(e)}
}
</script>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj, ctype="application/json; charset=utf-8"):
        raw = (obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, indent=2))
        raw = raw.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *a):
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self._send(200, DEMO_HTML, "text/html; charset=utf-8")
        if self.path == "/health":
            return self._send(200, {
                "status": "ok",
                "token_pool": pool_remaining(),
                "upstream": proto.BASE_AH,
                "stats": _stats,
                "blocker": "ah.dailyjoypro.com 的 ai/art/* 要求 Play Integrity (status 114)",
            })
        if self.path == "/v1/models":
            return self._send(200, {"object": "list", "data": [
                {"id": "umagic-txt2img", "object": "model", "owned_by": "hardstone"}]})
        return self._send(404, {"error": "not_found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        try:
            req = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid_json"})

        if self.path == "/v1/images/generations":
            prompt = req.get("prompt") or req.get("q")
            if not prompt:
                return self._send(400, {"error": "missing_prompt"})
            payload = {"nb": proto.NB, "ratio": req.get("size") or req.get("ratio") or "1:1",
                       "prompt": prompt}
            code, body = call_upstream(payload)
            if code != 200:
                return self._send(code, body)
            up = body["upstream"].get("data") or {}
            urls = up.get("image_url") or []
            if isinstance(urls, str):
                urls = [urls]
            return self._send(200, {"created": int(time.time()),
                                    "data": [{"url": u} for u in urls],
                                    "elapsed": body["elapsed"]})

        if self.path == "/umagic/txt2img":
            payload = {"nb": proto.NB, "ratio": req.get("ratio", "1:1"),
                       "prompt": req.get("prompt", "")}
            for k in ("style_id", "inspiration_id", "is_first", "is_translate", "xId"):
                if k in req:
                    payload[k] = req[k]
            return self._send(*call_upstream(payload))

        if self.path == "/umagic/raw":
            path = req.pop("path", "ai/art/txt2img/v2/")
            return self._send(*call_upstream(req, path=path))

        return self._send(404, {"error": "not_found"})


def main():
    left = pool_remaining()
    print(f"token pool: {left}  ->  http://127.0.0.1:{PORT}/")
    if left == 0:
        print("WARN: 池为空，先跑  python frida_mint.py <app_pid> 200 tokens.jsonl")
    print(f"upstream: {proto.BASE_AH}   (ai/art/* 需要 Play Integrity)")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()

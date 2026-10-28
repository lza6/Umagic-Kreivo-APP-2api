#!/usr/bin/env python3
"""
Umagic (Kreivo AI) 2API — aperogroup qwen-editing 链路
签名: x-api-signature = Base64(RSA-PKCS1v15(aperogroup_pub, "{ms_ts}@@@{api_key}@@@{6位nonce}"))
流程: presigned-link → S3 PUT → POST 生成 → 直接回 output URL (同步快速)
端口 8911: OpenAI 兼容 /v1/images/edits + /v1/chat/completions(伪) + /umagic/image/generate
"""
import base64, uuid, time, json, io, threading, urllib.request, ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

PUB = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5z8DrSdxAFy5ju27JzxUDGD5OdPRnKVrXPypiBVT7NK4ltgbcud3+Li3H1DiAFNvaSDPumZMEbAkfGWZ6s3KtiI7TRmZwQ2yyH6mug6GhrCLD6CZJUQ2CPmhO3JYTYOgN53E6hwm/Teb9I156S04qHjLLLBxk9Mklu5X06kdhMBYwHFAZ3oByeoWUryrQC0Mv9C5ZahKzoQNuJNL2sv+ws2e5Zaj8Rid4AjhvqB6dYhWP4QM+0IiNjs/j08aRgcyOrenbQEIieU+XF6mQWF2Jfg317e0KjWnpru+uPVVgrEn9rNvQeXu2u4SZhT6rnLQzBLbJrngNcNw3gXfxxsoowIDAQAB"
KEY = "sk-VqJLy0j9nKL7jL2Z95cGBmdkqf0prEsWCHmhRGVz6NWa1RfLIL"  # Alura RC 下发, Umagic mod 内置 key 已失效
APP_NAME = "AI_AIP894_Visionlab_Android"
BUNDLE = "com.ai.art.aiimagegenerator.aivideogenerator.aiphoto.aiart"
BASE = "https://api-img-gen-wrapper.aperogroup.ai"
PORT = 8911
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
_pub = load_der_public_key(base64.b64decode(PUB))
_lock = threading.Lock()

def sig_headers():
    with _lock:
        ts = str(int(time.time() * 1000))
    nonce = str(uuid.uuid4().int % 1000000).zfill(6)
    sig = base64.b64encode(_pub.encrypt(f"{ts}@@@{KEY}@@@{nonce}".encode(), padding.PKCS1v15())).decode()
    return {"App-version": "1.1.0", "Accept": "application/json", "App-name": APP_NAME,
            "Country-code": "US", "x-api-signature": sig, "x-api-keyid": KEY,
            "x-api-token": "not_get_api_token", "device": "android", "x-api-timestamp": ts,
            "x-api-bundleId": BUNDLE, "User-Agent": "okhttp/4.12.0"}

def http(req, timeout=90):
    return urllib.request.urlopen(req, context=CTX, timeout=timeout)

def generate_edit(img_bytes: bytes, prompt: str) -> str:
    """presign → S3 PUT → 生成, 返回 output URL"""
    r = http(urllib.request.Request(BASE + "/api/v5.1/qwen-editing/presigned-link", headers=sig_headers()))
    pd = json.loads(r.read())["data"]
    req = urllib.request.Request(pd["url"], data=img_bytes, method="PUT", headers={"Content-Type": "image/jpg"})
    http(req, timeout=120)
    body = json.dumps({"files": [pd["path"]], "mode": "IMAGE_EDITING",
                       "positivePrompt": prompt, "positivePrompt2": ""}).encode()
    r = http(urllib.request.Request(BASE + "/api/v5.1/qwen-editing", data=body,
             headers={**sig_headers(), "Content-Type": "application/json"}))
    d = json.loads(r.read())
    if d.get("statusCode") != 200:
        raise RuntimeError(f"upstream {d.get('statusCode')}: {d.get('message')}")
    return d["data"]["url"]

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"ok": True, "upstream": "aperogroup/qwen-editing"})
        if self.path == "/v1/models":
            return self._json(200, {"object": "list", "data": [{"id": "umagic-image-edit", "object": "model"}]})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n)
        try:
            if self.path == "/v1/images/edits":
                # multipart: 取 image 字段 + prompt 字段(极简解析)
                img, prompt = None, ""
                for part in raw.split(b"name=\"")[1:]:
                    name = part.split(b"\"")[0].decode(errors="ignore")
                    body = part.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
                    if name == "image": img = body
                    elif name == "prompt": prompt = body.decode(errors="ignore")
                if not img: return self._json(400, {"error": "missing image"})
                url = generate_edit(img, prompt or "enhance")
                return self._json(200, {"created": int(time.time()), "data": [{"url": url}]})

            if self.path == "/umagic/image/generate":
                d = json.loads(raw)
                img_b64 = d.get("image_base64", "")
                prompt = d.get("prompt", "enhance")
                img = base64.b64decode(img_b64) if img_b64 else None
                if not img: return self._json(400, {"error": "image_base64 required"})
                url = generate_edit(img, prompt)
                return self._json(200, {"success": True, "url": url, "elapsed_s": None})

            if self.path == "/v1/chat/completions":
                # 伪 chat: 把最后一条 user 消息当 prompt, 拒绝无图场景 (t2i 不在此链路)
                d = json.loads(raw)
                self._json(200, {"id": "chatcm-umagic", "object": "chat.completion", "created": int(time.time()),
                                 "model": d.get("model", "umagic"),
                                 "choices": [{"index": 0, "message": {"role": "assistant",
                                   "content": "Umagic 2API: 本渠道理只支持图像编辑(/v1/images/edits), 不支持文本对话。"},
                                   "finish_reason": "stop"}]})
                return
            self._json(404, {"error": "not found"})
        except Exception as e:
            self._json(502, {"error": str(e)})

if __name__ == "__main__":
    print(f"Umagic 2API demo @ http://0.0.0.0:{PORT}")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()

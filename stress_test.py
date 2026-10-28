#!/usr/bin/env python3
"""Umagic 2API 压测 — 并发真实图像编辑"""
import base64, json, time, threading, urllib.request, ssl, statistics, sys
CTX = ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE
URL = "http://127.0.0.1:8911/umagic/image/generate"
img = base64.b64encode(open("D:/apk-analysis/umagic/test.jpg","rb").read()).decode()
PROMPTS = ["van gogh style", "anime style", "cyberpunk neon", "oil painting", "pixar 3d style",
           "watercolor", "steampunk", "sketch pencil"]
results, times = [], []
lock = threading.Lock()
def worker(idx):
    body = json.dumps({"image_base64": img, "prompt": PROMPTS[idx % len(PROMPTS)]}).encode()
    t0 = time.time()
    try:
        r = urllib.request.urlopen(urllib.request.Request(URL, data=body,
            headers={"Content-Type":"application/json"}), timeout=180)
        d = json.loads(r.read())
        ok = bool(d.get("url"))
        with lock:
            results.append(ok); times.append(time.time()-t0)
            print(f"[{idx}] {'OK ' if ok else 'FAIL'} {time.time()-t0:.1f}s")
    except Exception as e:
        with lock:
            results.append(False); times.append(time.time()-t0)
            print(f"[{idx}] ERR {time.time()-t0:.1f}s {e}")
n = int(sys.argv[1]) if len(sys.argv)>1 else 6
threads=[threading.Thread(target=worker,args=(i,)) for i in range(n)]
t0=time.time()
for t in threads: t.start()
for t in threads: t.join()
ok=sum(results)
print(f"\n=== {ok}/{len(results)} success, total {time.time()-t0:.1f}s, p50={statistics.median(times):.1f}s, max={max(times):.1f}s ===")

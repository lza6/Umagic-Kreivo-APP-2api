# -*- coding: utf-8 -*-
"""并发压测：直连上游（不经网关），测量完整四段信封的时延与上游判定分布。

    python stress_test.py 10          # 10 并发
    python stress_test.py 10 http://127.0.0.1:8931/umagic/txt2img   # 打本地网关

注意：token 池是一次性消耗的，每次请求必须弹一对，所以并发上限 = 池内剩余数量。
"""
import json
import os
import statistics
import sys
import threading
import time

import proto

HERE = os.path.dirname(os.path.abspath(__file__))
PROMPT = "a cat sitting on a windowsill, watercolor"


def load_pool():
    p = os.path.join(HERE, "tokens.jsonl")
    out = []
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        d = json.loads(line)
                        if d.get("uid") and d.get("token"):
                            out.append(d)
                    except json.JSONDecodeError:
                        pass
    return out


def one(pair):
    import requests
    uid, tok = pair["uid"], pair["token"]
    body, _ = proto.wrap(json.dumps({"nb": proto.NB, "ratio": "1:1", "prompt": PROMPT},
                                    separators=(",", ":")), uid.replace("-", ""))
    t0 = time.time()
    try:
        r = requests.post(proto.BASE_AH + "/ai/art/txt2img/v2/", data=body,
                          headers=proto.headers(uid, tok), timeout=180)
        el = time.time() - t0
        j = r.json()
        return el, str(j.get("status")), str(j.get("message"))[:80], r.status_code
    except Exception as e:
        return time.time() - t0, "EXC", str(e)[:80], 0


def pct(vals, q):
    if not vals:
        return float("nan")
    s = sorted(vals)
    k = min(len(s) - 1, int(round((q / 100) * (len(s) - 1))))
    return s[k]


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    pool = load_pool()
    if len(pool) < n:
        print(f"token 池只有 {len(pool)} 条，不够 {n} 并发；先铸造："
              f"python frida_mint.py <pid> {n} tokens.jsonl")
        return 2
    batch = pool[:n]
    # consume them: the pool is single-use
    tmp = os.path.join(HERE, "tokens.jsonl.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for d in pool[n:]:
            f.write(json.dumps(d) + "\n")
    os.replace(tmp, os.path.join(HERE, "tokens.jsonl"))
    results = [None] * n
    wall0 = time.time()

    def worker(i):
        results[i] = one(batch[i])

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    wall = time.time() - wall0

    els = [r[0] for r in results if r]
    dist = {}
    for r in results:
        dist[r[1]] = dist.get(r[1], 0) + 1

    print(f"并发 {n}  墙钟 {wall:.2f}s  吞吐 {n/wall*60:.1f} req/min")
    print(f"时延 p50={pct(els,50):.2f}s p90={pct(els,90):.2f}s max={max(els):.2f}s")
    print(f"上游判定分布: {dist}")
    for r in results[:5]:
        print(f"  {r[0]:.2f}s  status={r[1]}  http={r[3]}  {r[2]}")
    with open(os.path.join(HERE, "stress_report.json"), "w", encoding="utf-8") as f:
        json.dump({"concurrency": n, "wall": wall, "p50": pct(els, 50),
                   "p90": pct(els, 90), "dist": dist,
                   "results": [{"elapsed": r[0], "status": r[1], "msg": r[2]} for r in results]},
                  f, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())

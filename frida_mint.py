"""Mint (uid, token) pairs on-device: paramsToken is a deterministic per-uid
function whose algorithm is native-obfuscated, so we batch-generate a pool."""
import frida, json, sys, time
SERIAL="emulator-5556"
JS=r"""
Java.perform(function () {
    var App = Java.use("umagic.ai.aiart.MyApp");
    var TU  = Java.use("a.bd.jniutils.TokenUtils");
    var tu  = TU.$new(); var ctx = App.t.value;
    var U   = Java.use("java.util.UUID");
    var n   = %d;
    for (var i = 0; i < n; i++) {
        var uid = String(U.randomUUID());
        var tok = null;
        try { tok = String(tu.f(ctx, uid)); } catch (e) { tok = null; }
        send({ uid: uid, token: tok });
    }
    send({ done: true });
});
"""
def main():
    n=int(sys.argv[2]) if len(sys.argv)>2 else 5
    out=sys.argv[3] if len(sys.argv)>3 else "D:/apk-analysis/umagic1120/tokens.jsonl"
    dev=frida.get_device(SERIAL,timeout=10)
    s=dev.attach(int(sys.argv[1]))
    sc=s.create_script(JS % n)
    got=[]
    def on_msg(m,d):
        p=m.get("payload",{})
        if p.get("done"): return
        if p.get("uid"): got.append(p)
    sc.on("message",on_msg); sc.load()
    t0=time.time()
    while len(got)<n and time.time()-t0<120: time.sleep(0.2)
    with open(out,"a",encoding="utf-8") as f:
        for p in got: f.write(json.dumps(p)+"\n")
    print(f"minted {len(got)} pairs -> {out}")
    for p in got[:3]: print("  ",p)
main()

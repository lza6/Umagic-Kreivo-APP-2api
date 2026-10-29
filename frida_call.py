# -*- coding: utf-8 -*-
"""Call the app's own TokenUtils on-device to harvest real token/ki/data
values for chosen uids, so the algorithm can be reimplemented off-device."""
import json
import time

import frida

SERIAL = "emulator-5556"
PKG = "umagic.ai.aiart.aiartgenrator"

JS = r"""
Java.perform(function () {
    var App = Java.use("umagic.ai.aiart.MyApp");
    var TU = Java.use("a.bd.jniutils.TokenUtils");
    var ctx = App.t.value;
    send({ kind: "ctx", cls: String(ctx.getClass().getName()) });

    var tu = TU.$new();
    var uids = [
        "a3f1c9d2-4b6e-4f27-9c1a-7e5b8d0c2f41",
        "00000000-0000-0000-0000-000000000000",
        "11111111-2222-3333-4444-555555555555",
        "abcdefgh-ijkl-mnop-qrst-uvwxyz012345"
    ];
    for (var i = 0; i < uids.length; i++) {
        var u = uids[i];
        var tok = null, err = null;
        try { tok = String(tu.f(ctx, u)); } catch (e) { err = String(e); }
        send({ kind: "paramsToken", uid: u, token: tok, err: err });
    }

    // envelope for a fixed uid -> lets us confirm key/iv derivation
    try {
        var r = TU.c(TU.$new(), ctx, '{"nb":"stn2_dailyjoy_us","ratio":"1:1","prompt":"cat"}');
        send({ kind: "envelope", value: String(r) });
    } catch (e) { send({ kind: "enverr", msg: String(e) }); }
});
"""


def on_message(msg, data):
    if msg.get("type") == "send":
        print(json.dumps(msg["payload"], ensure_ascii=False))
    else:
        print("[!!]", msg)


def main():
    dev = frida.get_device(SERIAL, timeout=10)
    import subprocess, sys
    try:
        pid = int(sys.argv[1])
    except Exception:
        pid = None
    try:
        if pid is None:
            pid = dev.get_process(PKG).pid
        print(f"attach pid={pid}")
        s = dev.attach(pid)
        sc = s.create_script(JS)
        sc.on("message", on_message)
        sc.load()
        time.sleep(8)
    except Exception as e:
        print("ERR", e)


if __name__ == "__main__":
    main()

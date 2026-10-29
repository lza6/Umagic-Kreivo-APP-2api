# -*- coding: utf-8 -*-
"""Attach to Umagic on the emulator and capture the real request envelope:
token header, uid, ki/data, and the outgoing URL."""
import sys
import time
import json

import frida

SERIAL = "emulator-5556"
PKG = "umagic.ai.aiart.aiartgenrator"

JS = r"""
Java.perform(function () {
    var out = {};

    function safe(fn) { try { return fn(); } catch (e) { return "ERR:" + e; } }

    // 1) token/ki/data producers
    try {
        var TU = Java.use("a.bd.jniutils.TokenUtils");
        TU.f.overload("android.content.Context", "java.lang.String").implementation = function (ctx, uid) {
            var r = TU.f(ctx, uid);
            send({ kind: "paramsToken", uid: uid, token: String(r) });
            return r;
        };
        TU.c.overload("a.bd.jniutils.TokenUtils", "android.content.Context", "java.lang.String").implementation = function (self, ctx, plain) {
            var r = TU.c(self, ctx, plain);
            send({ kind: "envelope_plain", plain: String(plain), enc: String(r) });
            return r;
        };
    } catch (e) { send({ kind: "hookerr", msg: "TokenUtils: " + e }); }

    // 2) outgoing headers (obfuscated okhttp: L8.w$a)
    try {
        var HB = Java.use("L8.w$a");
        globalThis.__hdr = null;
        HB.a.overload("java.lang.String", "java.lang.String").implementation = function (k, v) {
            globalThis.__hdr = (globalThis.__hdr || {});
            globalThis.__hdr[String(k)] = String(v);
            return this.a(k, v);
        };
        HB.b.implementation = function () {
            var r = this.b();
            var us = String(r.toString());
            if (us.indexOf("dailyjoypro") >= 0) {
                send({ kind: "request", url: us });
                send({ kind: "headers", lines: JSON.parse(JSON.stringify(globalThis.__hdr || {})) });
                globalThis.__hdr = null;
            }
            return r;
        };
    } catch (e) { send({ kind: "hookerr", msg: "L8.w$a: " + e }); }

    // 3) response body (obfuscated okhttp: L8.B)
    try {
        var B = Java.use("L8.B");
        B.y.implementation = function () {
            var s = this.y();
            send({ kind: "response", body: String(s).substring(0, 1500) });
            return s;
        };
    } catch (e) { send({ kind: "hookerr", msg: "L8.B: " + e }); }
});
"""


def on_message(msg, data):
    if msg.get("type") == "send":
        p = msg["payload"]
        k = p.get("kind")
        if k == "headers":
            print("[HEADERS]")
            for line in p["lines"]:
                print("   ", line)
        elif k == "request":
            print(f"\n[REQ] {p['url']}")
        elif k == "response":
            print(f"[RESP] {p['body'][:600]}")
        else:
            print(f"[{k}] {json.dumps(p, ensure_ascii=False)[:900]}")
    else:
        print("[!!]", msg)


def main():
    dev = frida.get_device(SERIAL, timeout=10)
    try:
        pid = dev.get_process(PKG).pid
    except Exception:
        pid = dev.spawn([PKG])
        print(f"spawned pid={pid}")
        device_session = dev.attach(pid)
        script = device_session.create_script(JS)
        script.on("message", on_message)
        script.load()
        dev.resume(pid)
        time.sleep(45)
        return
    print(f"attaching to running pid={pid}")
    s = dev.attach(pid)
    sc = s.create_script(JS)
    sc.on("message", on_message)
    sc.load()
    time.sleep(45)


if __name__ == "__main__":
    main()

import frida, json, time, sys
SERIAL="emulator-5556"
JS=r"""
Java.perform(function () {
    var App = Java.use("umagic.ai.aiart.MyApp");
    var TU = Java.use("a.bd.jniutils.TokenUtils");
    var tu = TU.$new(); var ctx = App.t.value;

    try {
        TU.d.overload("java.lang.String","java.lang.String","java.lang.String").implementation = function (p,k,iv) {
            send({ kind:"aes", plain:String(p), key:String(k), iv:String(iv) });
            return TU.d(p,k,iv);
        };
    } catch(e){ send({kind:"hookerr", msg:"d: "+e}); }

    var u="a3f1c9d2-4b6e-4f27-9c1a-7e5b8d0c2f41";
    send({kind:"tok1", v:String(tu.f(ctx,u))});
    send({kind:"tok2", v:String(tu.f(ctx,u))});
    try { TU.c(TU.$new(), ctx, '{"x":1}'); } catch(e){ send({kind:"e", msg:"c: "+e}); }
});
"""
dev=frida.get_device(SERIAL,timeout=10)
pid=int(sys.argv[1])
s=dev.attach(pid); sc=s.create_script(JS)
sc.on("message", lambda m,d: print(json.dumps(m.get("payload",m), ensure_ascii=False)))
sc.load(); time.sleep(6)

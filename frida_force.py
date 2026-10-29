import frida, json, sys, time
SERIAL="emulator-5556"
JS=r"""
Java.perform(function () {
    var HB = Java.use("L8.w$a");
    globalThis.__h = {};
    HB.a.overload("java.lang.String","java.lang.String").implementation = function (k,v) {
        globalThis.__h[String(k)] = String(v);
        return this.a(k,v);
    };
    HB.b.implementation = function () {
        var r = this.b();
        var s = String(r.toString());
        if (s.indexOf("dailyjoypro") >= 0) {
            send({ kind:"request", url:s, headers: JSON.parse(JSON.stringify(globalThis.__h)) });
            globalThis.__h = {};
        }
        return r;
    };
    // fire a real request through the app's own client
    var P = Java.use("p8.p");
    var Cb = Java.registerClass({
        name: "umagic.Cb",
        implements: [P],
        methods: { j: function (a, b) { send({ kind:"cb", v: String(a) }); return null; } }
    });
    var R = Java.use("E9.r");
    var r = R.$new(false);
    try { r.c("probe_1x1.jpg", Cb.$new()); send({kind:"fired"}); }
    catch (e) { send({ kind:"err", m:"c: "+e }); }
    setTimeout(function(){ try { r.h(Cb.$new()); send({kind:"fired2"}); } catch(e){ send({kind:"err", m:"h: "+e}); } }, 3000);
});
"""
dev=frida.get_device(SERIAL,timeout=10)
s=dev.attach(int(sys.argv[1])); sc=s.create_script(JS)
sc.on("message", lambda m,d: print(json.dumps(m.get("payload",m), ensure_ascii=False, indent=None)[:1400]))
sc.load(); time.sleep(14)

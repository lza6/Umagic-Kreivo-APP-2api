# -*- coding: utf-8 -*-
"""Emulate libtk.so's JNI_OnLoad to recover the RegisterNatives table
(method name -> fn ptr), then call publicKey() / paramsToken()."""
import struct
import sys
import os
import unicorn
from unicorn.arm64_const import *
from soemu import Emulator, BASE_JNI, BASE_STUBS

SO = "D:/apk-analysis/umagic1120/unz/lib/arm64-v8a/libtk.so"
PKG = "umagic.ai.aiart.aiartgenrator"


def X(i):
    return globals()[f"UC_ARM64_REG_X{i}"]


def main():
    e = Emulator(SO)
    uc = e.uc

    def call_ret(env, v):
        x30 = uc.reg_read(UC_ARM64_REG_LR)
        uc.reg_write(UC_ARM64_REG_PC, x30)
        uc.reg_write(UC_ARM64_REG_X0, v & 0xFFFF_FFFF_FFFF_FFFF)

    def j_find_class(env):
        name = e.heap.read_cstr(uc.reg_read(X(1))).decode()
        cid = 0x9000 + len(e.jclasses)
        e.jclasses[cid] = name
        print(f"  [FindClass] {name} -> {cid:#x}")
        return call_ret(env, cid)

    def j_register_natives(env):
        clazz = uc.reg_read(X(1))
        methods = uc.reg_read(X(2))
        count = struct.unpack("<i", struct.pack("<I", uc.reg_read(X(3)) & 0xFFFFFFFF))[0]
        print(f"  [RegisterNatives] class={clazz:#x} count={count}")
        for i in range(count):
            base = methods + i * 24
            name_p, sig_p, fn = struct.unpack("<QQQ", bytes(uc.mem_read(base, 24)))
            nm = e.heap.read_cstr(name_p).decode()
            sg = e.heap.read_cstr(sig_p).decode()
            e.registered_natives.append((nm, sg, fn))
            print(f"     {nm:26s} {sg:30s} -> {fn:#x}")
        return call_ret(env, 0)

    def j_new_string_utf(env):
        p = uc.reg_read(X(1))
        s = e.heap.read_cstr(p)
        sid = e.next_jstr
        e.next_jstr += 1
        e.strings[sid] = s
        return call_ret(env, sid)

    e.jni_hooks[6] = j_find_class
    e.jni_hooks[215] = j_register_natives
    e.jni_hooks[167] = j_new_string_utf

    # fake JavaVM with a GetEnv (index 6) that hands back our JNIEnv
    vm_vt = BASE_JNI + 0x3000
    uc.mem_write(BASE_JNI + 0x2000, struct.pack("<Q", vm_vt))
    vt = bytearray(32 * 8)
    getenv_stub = BASE_STUBS + 0x3000
    struct.pack_into("<Q", vt, 6 * 8, getenv_stub)
    uc.mem_write(vm_vt, bytes(vt))

    def hook(uc_, address, size, user):
        if address == getenv_stub:
            # GetEnv(vm, void** env, jint version)
            uc_.mem_write(uc_.reg_read(X(1)), struct.pack("<Q", BASE_JNI))
            return call_ret(uc_, 0)
        return None

    uc.hook_add(unicorn.UC_HOOK_CODE, hook)

    try:
        e.call(0x13564, [BASE_JNI + 0x2000, 0], timeout=60_000_000)
    except Exception as ex:
        print("JNI_OnLoad emulation stopped:", ex)

    print("\n=== registered natives ===")
    for nm, sg, fn in e.registered_natives:
        print(f"  {nm:26s} {sg:30s} {fn:#x}")

    want = {nm: (sg, fn) for nm, sg, fn in e.registered_natives}

    if not want:
        want = {nm: (sg, fn) for nm, sg, fn in
                (("publicKey", "()Ljava/lang/String;", 0xed24),
                 ("paramsToken", "(Ljava/lang/String;)Ljava/lang/String;", 0xed20))}

    # 1) publicKey() -> jstring
    if "publicKey" in want and want["publicKey"][1]:
        fn = want["publicKey"][1]
        cls = 0x9000
        ret = e.call(fn, [BASE_JNI, cls])
        key = e.strings.get(ret, b"")
        print(f"\npublicKey() -> len={len(key)}")
        print(key.decode("latin-1"))

    # 2) paramsToken(String)
    if "paramsToken" in want and want["paramsToken"][1]:
        fn = want["paramsToken"][1]
        uid = "a3f1c9d2-4b6e-4f27-9c1a-7e5b8d0c2f41"
        js = e.new_string(uid)
        ret = e.call(fn, [BASE_JNI, 0x9000, js])
        tok = e.strings.get(ret, b"")
        print(f"\nparamsToken({uid}) -> {tok!r}")


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""Extract every (ciphertext, key) pair passed to E2/X->d(...) from the smali
tree, then decrypt all of them with the emulated libhscore.so."""
import re
import sys
import glob
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soemu import Emulator, BASE_JNI

SMALI_ROOT = sys.argv[1] if len(sys.argv) > 1 else "D:/apk-analysis/umagic1120/apktool_full"
OUT = sys.argv[2] if len(sys.argv) > 2 else "D:/apk-analysis/umagic1120/strings_decoded.txt"

CONST = re.compile(r'const-string(?:/jumbo)?\s+(v\d+|p\d+),\s*"([^"]*)"')
INVOKE = re.compile(r'invoke-static\s+\{(v\d+|p\d+),\s*(v\d+|p\d+)\},\s*LE2/X;->d\(')


def extract():
    pairs = []
    for f in sorted(glob.glob(os.path.join(SMALI_ROOT, "smali*", "**", "*.smali"), recursive=True)):
        with open(f, encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        regs = {}
        for ln in lines:
            m = CONST.search(ln)
            if m:
                regs[m.group(1)] = m.group(2)
                continue
            m = INVOKE.search(ln)
            if m:
                a, b = m.group(1), m.group(2)
                if a in regs and b in regs:
                    pairs.append((regs[a], regs[b], os.path.relpath(f, SMALI_ROOT)))
                continue
            # a register gets clobbered by most other ops; be lenient but drop
            # obvious writes so stale values are not paired
            m2 = re.match(r'\s*(?:move-result|move|new-instance)[^,]*,?\s*(v\d+|p\d+)?', ln)
            if m2 and m2.group(1):
                regs.pop(m2.group(1), None)
    return pairs


def main():
    pairs = extract()
    # dedupe before touching the emulator: the same (cipher,key) recurs all over
    uniq, seen0 = [], set()
    for ct, key, where in pairs:
        if (ct, key) in seen0:
            continue
        seen0.add((ct, key))
        uniq.append((ct, key, where))
    print(f"found {len(pairs)} pairs, {len(uniq)} unique")
    emu = Emulator("D:/apk-analysis/umagic1120/unz/lib/arm64-v8a/libhscore.so")
    rows = []
    for ct, key, where in uniq:
        try:
            cid = emu.new_string(ct)
            kid = emu.new_string(key)
            ret = emu.call(0x4254, [BASE_JNI, 0, cid, kid])
            if ret in emu.arrays:
                plain = bytes(emu.arrays[ret])
            else:
                plain = emu.get_string(ret)
            try:
                p = plain.decode("utf-8")
            except UnicodeDecodeError:
                p = plain.decode("latin-1")
            rows.append({"cipher": ct, "key": key, "plain": p, "src": where})
        except Exception as e:                      # emulation can run out of heap
            rows.append({"cipher": ct, "key": key, "plain": f"<ERR {e}>", "src": where})
            emu = Emulator("D:/apk-analysis/umagic1120/unz/lib/arm64-v8a/libhscore.so")
    with open(OUT, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(f"{r['plain']}\t{r['key']}\t{r['src']}\n")
    print(f"decoded {len(rows)} -> {OUT}")
    for r in rows:
        if r["plain"].startswith("<ERR"):
            continue
        print(f"  {r['plain']}")


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""Minimal ARM64 Android .so emulator with JNI stubs.

Purpose: run libhscore.so / libtk.so native JNI functions on Windows/x86
without an Android device.  Handles:
  * PT_LOAD mapping, AARCH64_RELATIVE + JUMP_SLOT relocations
  * a bump heap, a stack, a TLS block (for the stack canary)
  * out-of-band implementations of the libc imports the libs actually use
  * a fake JNIEnv function table so GetStringUTFChars / NewStringUTF etc. work
"""
import struct
import unicorn
from unicorn import *
from unicorn.arm64_const import *
import lief

BASE_HEAP = 0x1000_0000
HEAP_SIZE = 0x0200_0000
BASE_STACK = 0x3000_0000
STACK_SIZE = 0x0020_0000
BASE_TLS = 0x4000_0000
BASE_JNI = 0x5000_0000
BASE_STUBS = 0x6000_0000
PAGE = 0x1000


class GuestHeap:
    def __init__(self, uc, base, size):
        self.uc = uc
        self.base = base
        self.size = size
        self.cur = base

    def alloc(self, n, zero=True):
        n = max(int(n), 1)
        p = (self.cur + 15) & ~15
        if p + n > self.base + self.size:
            raise MemoryError("guest heap exhausted")
        self.cur = p + n
        if zero:
            self.uc.mem_write(p, b"\x00" * n)
        return p

    def write(self, data):
        p = self.alloc(len(data))
        self.uc.mem_write(p, data)
        return p

    def cstr(self, s):
        if isinstance(s, str):
            s = s.encode()
        return self.write(s + b"\x00")

    def read_cstr(self, p, limit=1 << 20):
        out = bytearray()
        while len(out) < limit:
            b = self.uc.mem_read(p + len(out), 1)[0]
            if b == 0:
                break
            out.append(b)
        return bytes(out)


class Emulator:
    def __init__(self, so_path, verbose=False):
        self.path = so_path
        self.verbose = verbose
        self.bin = lief.parse(so_path)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.mapped = {}          # name -> (guest_string_id, bytes)
        self.strings = {}         # jstring id -> bytes
        self.next_jstr = 1
        self.imports = {}         # python handler table for libc
        self.extra_imports = {}   # name -> python fn  (injected by caller)
        self.fopen_files = {}
        # fake filesystem seen by the native code
        self._fake_files = {
            "/proc/self/cmdline": "umagic.ai.aiart.aiartgenrator",
            "/proc/4242/cmdline": "umagic.ai.aiart.aiartgenrator",
        }
        self.arrays = {}
        self._file_handles = {}
        self.jni_hooks = {}
        self.jclasses = {}
        self.registered_natives = []
        self._map()
        self.heap = GuestHeap(self.uc, BASE_HEAP, HEAP_SIZE)
        self._reloc()
        self._jni()
        self._tls()
        self._setup_imports()
        self.log = []

    # ---------- mapping ----------
    def _map(self):
        # ELF PT_LOAD segments overlap (minexport perms); map the whole span once.
        segs = [s for s in self.bin.segments if s.virtual_size]
        lo = min(s.virtual_address & ~(PAGE - 1) for s in segs)
        hi = max((s.virtual_address + s.virtual_size + PAGE - 1) & ~(PAGE - 1) for s in segs)
        self.uc.mem_map(lo, hi - lo, UC_PROT_ALL)
        for seg in segs:
            data = bytes(seg.content)
            if data:
                self.uc.mem_write(seg.virtual_address, data)
        for base, sz in ((BASE_HEAP, HEAP_SIZE), (BASE_STACK, STACK_SIZE),
                         (BASE_TLS, PAGE * 4), (BASE_JNI, PAGE * 16), (BASE_STUBS, PAGE * 4)):
            self.uc.mem_map(base, sz, UC_PROT_ALL)

    def _reloc(self):
        # base is 0, so RELATIVE addend goes back verbatim
        for r in self.bin.relocations:
            tname = r.type.name if hasattr(r.type, "name") else str(r.type)
            if "RELATIVE" in tname:
                self.uc.mem_write(r.address, struct.pack("<Q", r.addend & 0xFFFF_FFFF_FFFF_FFFF))
            elif "ABS64" in tname:
                if r.has_symbol and r.symbol.value:
                    self.uc.mem_write(r.address, struct.pack("<Q", r.symbol.value))
            elif "GLOB_DAT" in tname:
                if r.has_symbol and r.symbol.value:
                    self.uc.mem_write(r.address, struct.pack("<Q", r.symbol.value))
                else:
                    # imported data object (e.g. _ctype_): hand out a real table
                    name = r.symbol.name if r.has_symbol else "_data"
                    p = self._data_obj(name)
                    self.uc.mem_write(r.address, struct.pack("<Q", p))
            elif "JUMP_SLOT" in tname:
                name = r.symbol.name if r.has_symbol else None
                if name is None:
                    continue
                sym = r.symbol
                if sym.value:            # locally defined (weak) function
                    self.uc.mem_write(r.address, struct.pack("<Q", sym.value))
                else:
                    self.imports_got = getattr(self, "imports_got", {})
                    self.imports_got[name] = r.address

    def _data_obj(self, name):
        """Backing object for an imported data symbol.

        The lib dereferences the GOT slot and then dereferences *that* to reach
        the real array, so hand back a slot pointing at the table.
        """
        tbl_addr = self.heap.alloc(512)
        if name == "_ctype_":
            # bionic: _ctype_[1+256], index = c+1
            tbl = bytearray(512)
            for c in range(256):
                f = 0
                if 65 <= c <= 90:
                    f |= 0x01 | 0x40
                elif 97 <= c <= 122:
                    f |= 0x02 | 0x40
                elif 48 <= c <= 57:
                    f |= 0x04 | 0x40
                elif c in (32, 9, 10, 11, 12, 13):
                    f |= 0x08
                elif c < 32 or c == 127:
                    f |= 0x20
                elif c < 127:
                    f |= 0x10
                tbl[(c + 1) & 0x1FF] = f
            self.uc.mem_write(tbl_addr, bytes(tbl))
        slot = self.heap.alloc(8)
        self.uc.mem_write(slot, struct.pack("<Q", tbl_addr))
        return slot
    def _tls(self):
        self.uc.mem_write(BASE_TLS, b"\x00" * PAGE)
        self.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, BASE_TLS)

    # ---------- JNI ----------
    def _jni(self):
        # canonical JNIEnv layout: JNIEnv* -> pointer to function table
        self.jni_vt = BASE_JNI + 0x1000
        self.uc.mem_write(BASE_JNI, struct.pack("<Q", self.jni_vt))
        tbl = bytearray(512 * 8)
        self.jni_slots = {}
        for idx in (4, 5, 6, 23, 31, 33, 94, 113, 167, 169, 170, 171, 176, 200, 208, 215):
            addr = BASE_STUBS + 0x800 + idx * 8
            self.jni_slots[addr] = idx
            struct.pack_into("<Q", tbl, idx * 8, addr)
        self.uc.mem_write(self.jni_vt, bytes(tbl))
        self.uc.hook_add(UC_HOOK_CODE, self._hook)

    def _setup_imports(self):
        self.imp_base = BASE_STUBS + 0x2000
        self.imp_names = {}
        got = getattr(self, "imports_got", {})
        for i, (name, addr) in enumerate(sorted(got.items())):
            stub = self.imp_base + i * 8
            self.imp_names[stub] = name
            self.uc.mem_write(addr, struct.pack("<Q", stub))

    # ---------- hooks ----------
    def _ret(self, v=0):
        x30 = self.uc.reg_read(UC_ARM64_REG_LR)
        self.uc.reg_write(UC_ARM64_REG_PC, x30)
        self.uc.reg_write(UC_ARM64_REG_X0, v & 0xFFFF_FFFF_FFFF_FFFF)

    def _arg(self, i):
        return self.uc.reg_read(globals()[f"UC_ARM64_REG_X{i}"])

    def _hook(self, uc, address, size, user):
        if address in self.jni_slots:
            return self._jni_call(self.jni_slots[address])
        if address in self.imp_names:
            return self._libc_call(self.imp_names[address])
        return None

    def _jni_call(self, idx):
        uc = self.uc
        if idx in self.jni_hooks:
            return self.jni_hooks[idx](self)
        if idx == 169:      # GetStringUTFChars(env, jstring, isCopy)
            js = self._arg(1)
            data = self.strings.get(js, b"")
            p = self.heap.write(data + b"\x00")
            return self._ret(p)
        if idx == 170:      # ReleaseStringUTFChars
            return self._ret(0)
        if idx == 171:      # GetArrayLength
            arr = self._arg(1)
            if arr in self.arrays:
                return self._ret(len(self.arrays[arr]))
            return self._ret(len(self.strings.get(arr, b"")))
        if idx == 176:      # NewByteArray
            n = self._arg(1)
            aid = self.next_jstr
            self.next_jstr += 1
            self.arrays[aid] = bytearray(n)
            return self._ret(aid)
        if idx == 200:      # GetByteArrayRegion(env, arr, start, len, buf)
            arr, start, ln, buf = self._arg(1), self._arg(2), self._arg(3), self._arg(4)
            data = bytes(self.arrays.get(arr, b""))[start:start + ln]
            if data:
                self.uc.mem_write(buf, data)
            return self._ret(0)
        if idx == 208:      # SetByteArrayRegion(env, arr, start, len, buf)
            arr, start, ln, buf = self._arg(1), self._arg(2), self._arg(3), self._arg(4)
            data = bytes(self.uc.mem_read(buf, ln))
            a = self.arrays.setdefault(arr, bytearray())
            if len(a) < start + ln:
                a.extend(b"\x00" * (start + ln - len(a)))
            a[start:start + ln] = data
            return self._ret(0)
        if idx == 167:      # NewStringUTF
            p = self._arg(1)
            s = self.heap.read_cstr(p)
            sid = self.next_jstr
            self.next_jstr += 1
            self.strings[sid] = s
            return self._ret(sid)
        return self._ret(0)

    def _libc_call(self, name):
        uc = self.uc
        a = [self._arg(i) for i in range(5)]
        if name == "malloc":
            return self._ret(self.heap.alloc(a[0]))
        if name == "calloc":
            return self._ret(self.heap.alloc(a[0] * a[1]))
        if name == "realloc":
            old, n = a[0], a[1]
            if old == 0:
                return self._ret(self.heap.alloc(n))
            try:
                data = bytes(uc.mem_read(old, n))
            except UcError:
                data = b""
            p = self.heap.alloc(n)
            if data:
                uc.mem_write(p, data[:n])
            return self._ret(p)
        if name == "free":
            return self._ret(0)
        if name == "memset":
            uc.mem_write(a[0], bytes([a[1] & 0xFF]) * a[2])
            return self._ret(a[0])
        if name == "memcpy":
            data = bytes(uc.mem_read(a[1], a[2]))
            uc.mem_write(a[0], data)
            return self._ret(a[0])
        if name == "memmove":
            data = bytes(uc.mem_read(a[1], a[2]))
            uc.mem_write(a[0], data)
            return self._ret(a[0])
        if name in ("strlen", "__strlen_chk"):
            return self._ret(len(self.heap.read_cstr(a[0])))
        if name == "strcmp":
            s1 = self.heap.read_cstr(a[0]); s2 = self.heap.read_cstr(a[1])
            return self._ret(0 if s1 == s2 else (1 if s1 > s2 else -1))
        if name == "strncpy":
            dst, src, n = a[0], a[1], a[2]
            data = self.heap.read_cstr(src)[:n]
            data = data + b"\x00" * (n - len(data))
            uc.mem_write(dst, data)
            return self._ret(dst)
        if name == "strcat":
            dst, src = a[0], a[1]
            cur = self.heap.read_cstr(dst)
            uc.mem_write(dst + len(cur), self.heap.read_cstr(src) + b"\x00")
            return self._ret(dst)
        if name == "__strncat_chk":
            dst, src, n = a[0], a[1], a[2]
            cur = self.heap.read_cstr(dst)
            add = self.heap.read_cstr(src)[:n]
            uc.mem_write(dst + len(cur), add + b"\x00")
            return self._ret(dst)
        if name == "strstr":
            hay = self.heap.read_cstr(a[0]); needle = self.heap.read_cstr(a[1])
            i = hay.find(needle)
            return self._ret(0 if i < 0 else a[0] + i)
        if name == "strchr":
            s = self.heap.read_cstr(a[0]); ch = a[1] & 0xFF
            i = s.find(bytes([ch]))
            return self._ret(0 if i < 0 else a[0] + i)
        if name == "__android_log_print":
            return self._ret(0)
        if name == "getpid":
            return self._ret(4242)
        if name == "fopen":
            path = self.heap.read_cstr(a[0]).decode("latin-1")
            hid = len(self._file_handles) + 1
            self._file_handles[hid] = [path, 0]
            return self._ret(0x7000 + hid)
        if name == "fgets":
            buf, n, fh = a[0], a[1], a[2]
            h = self._file_handles.get(fh - 0x7000)
            if not h:
                return self._ret(0)
            path, pos = h
            data = self._fake_files.get(path)
            if data is None:
                return self._ret(0)
            if pos >= len(data):
                return self._ret(0)
            chunk = data[pos:pos + max(n - 1, 1)]
            h[1] = pos + len(chunk)
            self.uc.mem_write(buf, chunk.encode("latin-1") + b"\x00")
            return self._ret(buf)
        if name == "fread":
            buf, sz, cnt, fh = a[0], a[1], a[2], a[3]
            h = self._file_handles.get(fh - 0x7000)
            if not h:
                return self._ret(0)
            path, pos = h
            data = self._fake_files.get(path, "")
            want = sz * cnt
            chunk = data[pos:pos + want]
            h[1] = pos + len(chunk)
            self.uc.mem_write(buf, chunk.encode("latin-1"))
            return self._ret(len(chunk) // max(sz, 1))
        if name == "fclose":
            return self._ret(0)
        if name == "ferror":
            return self._ret(0)
        if name == "__stack_chk_fail":
            raise RuntimeError("stack check failed")
        if name == "__vsprintf_chk":
            # dst, flag, dstlen, fmt, va_list
            dst, dstlen, fmt_p, va = a[0], a[2], a[3], a[4]
            out = self._format(fmt_p, va)
            uc.mem_write(dst, out[:dstlen - 1] + b"\x00")
            return self._ret(len(out))
        if name in self.extra_imports:
            return self._ret(self.extra_imports[name](self, a))
        # generous default: return 0
        if self.verbose:
            print(f"  [libc stub] {name}({a[:3]}) -> 0")
        return self._ret(0)

    def _format(self, fmt_p, va_p):
        """Very small printf: supports %s %d %u %02x %x %lld etc."""
        fmt = self.heap.read_cstr(fmt_p).decode("latin-1")
        args = []
        off = 0
        for _ in range(8):
            args.append(struct.unpack("<Q", bytes(self.uc.mem_read(va_p + off, 8)))[0])
            off += 8
        out, ai, i = [], 0, 0
        while i < len(fmt):
            c = fmt[i]
            if c != "%":
                out.append(c); i += 1; continue
            j = i + 1
            while j < len(fmt) and fmt[j] in "-+ #0.123456789lhqjzt":
                j += 1
            conv = fmt[j] if j < len(fmt) else ""
            spec = fmt[i:j + 1]
            v = args[ai] if ai < len(args) else 0
            ai += 1
            if conv == "s":
                out.append(self.heap.read_cstr(v).decode("latin-1"))
            elif conv in "di":
                out.append(str(struct.unpack("<i", struct.pack("<I", v & 0xFFFFFFFF))[0]))
            elif conv in "uxX":
                if "02x" in spec:
                    out.append("%02x" % (v & 0xFF))
                elif conv == "x":
                    out.append("%x" % v)
                else:
                    out.append(str(v))
            elif conv == "c":
                out.append(chr(v & 0xFF))
            elif conv == "p":
                out.append(hex(v))
            else:
                out.append(spec)
            i = j + 1
        return "".join(out).encode("latin-1")

    # ---------- calling ----------
    def new_string(self, s):
        sid = self.next_jstr
        self.next_jstr += 1
        self.strings[sid] = s.encode() if isinstance(s, str) else s
        return sid

    def get_string(self, sid):
        v = self.strings.get(sid, b"")
        return v

    def call(self, func_addr, args, timeout=30_000_000, count=5_000_000):
        sp = BASE_STACK + STACK_SIZE - 0x1000
        sp &= ~0xF
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_LR, 0xDEAD_0000)   # sentinel
        for i, v in enumerate(args):
            self.uc.reg_write(globals()[f"UC_ARM64_REG_X{i}"], v & 0xFFFF_FFFF_FFFF_FFFF)
        try:
            self.uc.emu_start(func_addr, 0xDEAD_0000, timeout=timeout, count=count)
        except UcError as e:
            raise RuntimeError(f"emulation error at PC={self.uc.reg_read(UC_ARM64_REG_PC):#x}: {e}")
        return self.uc.reg_read(UC_ARM64_REG_X0)

    def call_cstr(self, func_addr, cstrs, pre=None, **kw):
        args = []
        if pre:
            args.extend(pre)
        for s in cstrs:
            args.append(self.heap.cstr(s))
        return self.call(func_addr, args, **kw)

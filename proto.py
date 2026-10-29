# -*- coding: utf-8 -*-
"""Umagic v1.12.0 protocol kernel: request envelope (AES-128-CBC + RSA wrap)."""
import base64
import json
import os
import time
import uuid as _uuid

import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key

# Recovered from libtk.so `publicKey()` (392-char X509/SPKI, base64)
RSA_PUB_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo+yvc35R8VPsfy1ScmQap+vVg/IYTcZCiJP5iiIo0HFLBrfDhwZ30wpvQ8lpezTN3exdZU3edIspp+weCgifbjFEyI7/Ecce7GTYXZyLncBrjzvO6IohPnaz/hx7+Uy6eNw8DNk15sxcJrQeSOULtOWJJ8dJ2IbR1eRIp0PXwJeXqdfoT52WzT/FaNzwh7sWmt4Zl8cw9o9JvdTqdU3WsCsdqsOXWIgyP/UIFWM+uu7P1xJ/DY40nMokHlG+fDdiT0us5Vu4LNUt3Er8OOZynnOESSQUocSvpb9UOcK5SurLCjWsk0RnQY2RBQluBnC9isJK5RC9FyK/5ezjmaQ1hQIDAQAB"
)

BASE_GP = "https://gp.dailyjoypro.com/"      # u9/f->d (used when RetrofitUtil(true))
BASE_AH = "https://ah.dailyjoypro.com"       # u9/f->c
PKG = "umagic.ai.aiart.aiartgenrator"
PROJECT = "Umagic"
VERSION_CODE = "112002"
NB = "stn2_dailyjoy_us"                       # u9/f->g with "gs://" stripped

_pub = load_der_public_key(base64.b64decode(RSA_PUB_B64))


def _pkcs7(b: bytes, n: int = 16) -> bytes:
    pad = n - len(b) % n
    return b + bytes([pad]) * pad


def wrap(plaintext: str, uid: str = None):
    """Build the {rv,ki,data} envelope. Returns (json_string, uid)."""
    if uid is None:
        uid = _uuid.uuid4().hex
    key = uid[0:16].encode()
    iv = uid[16:32].encode()
    ki = base64.b64encode(_pub.encrypt(uid.encode(), padding.PKCS1v15())).decode()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    data = base64.b64encode(enc.update(_pkcs7(plaintext.encode())) + enc.finalize()).decode()
    return json.dumps({"rv": 1, "ki": ki, "data": data}, separators=(",", ":")), uid


def headers(uid: str, token: str = ""):
    h = {
        "uid": uid,
        "versionCode": VERSION_CODE,
        "version": VERSION_CODE,
        "pkg": PKG,
        "Content-Type": "application/json",
        "Accept-Version": "v1",
        "platform": "Android",
        "project": PROJECT,
    }
    if token:
        h["token"] = token
    return h


def post(path: str, payload: dict, base: str = BASE_GP, token: str = "", timeout=180,
         uid: str = None, extra_headers: dict = None):
    body, uid = wrap(json.dumps(payload, separators=(",", ":")), uid)
    h = headers(uid, token)
    if extra_headers:
        h.update(extra_headers)
    url = base.rstrip("/") + "/" + path.lstrip("/")
    t0 = time.time()
    r = requests.post(url, data=body, headers=h, timeout=timeout)
    dt = time.time() - t0
    try:
        j = r.json()
    except Exception:
        j = {"_raw": r.text[:600]}
    return r.status_code, j, dt, uid


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "ai/art/txt2img/v2/"
    payload = {"nb": NB, "ratio": "1:1", "prompt": "a cat sitting on a windowsill, watercolor"}
    code, j, dt, uid = post(path, payload)
    print(f"HTTP {code}  {dt:.2f}s  uid={uid}")
    print(json.dumps(j, ensure_ascii=False)[:1500])

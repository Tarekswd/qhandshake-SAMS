"""Independent re-implementation of the QHandshake key schedule using only Python's stdlib
(hashlib/hmac). Its output is pasted into tests/kat.rs; agreement between the two is a
differential check of the Rust key schedule. Run: python tools/kat.py (exit 1 on mismatch)"""
import hashlib
import hmac

H = lambda b: hashlib.sha256(b).digest()
PREFIX = b"qh01 "


def extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def expand_label(secret, label, ctx, n):
    full = PREFIX + label
    info = n.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return expand(secret, info, n)


def derive(secret, label, th):
    return expand_label(secret, label, th, 32)


shared = bytes(range(1, 65))  # 64-byte hybrid secret
th_hello = H(b"hello")
th_fin = H(b"fin")

early = extract(b"\0" * 32, b"\0" * 32)
hs = extract(derive(early, b"derived", H(b"")), shared)
c_hs = derive(hs, b"c hs traffic", th_hello)
s_hs = derive(hs, b"s hs traffic", th_hello)
master = extract(derive(hs, b"derived", H(b"")), b"\0" * 32)
c_ap = derive(master, b"c ap traffic", th_fin)
s_ap = derive(master, b"s ap traffic", th_fin)
fin = hmac.new(expand_label(s_hs, b"finished", b"", 32), th_fin, hashlib.sha256).digest()

rust = open(__import__("pathlib").Path(__file__).parent.parent / "tests" / "kat.rs").read()
missing = 0
for name, v in [("hs", hs), ("c_hs", c_hs), ("s_hs", s_hs), ("c_ap", c_ap), ("s_ap", s_ap), ("fin", fin)]:
    ok = v.hex() in rust
    missing += not ok
    print(f"{name} {v.hex()} {'matches tests/kat.rs' if ok else 'MISSING from tests/kat.rs'}")
raise SystemExit(1 if missing else 0)

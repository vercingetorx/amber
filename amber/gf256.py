"""GF(256) arithmetic helpers using the AES polynomial 0x11B.

Includes optional NumPy-accelerated paths for vectorized byte operations
when NumPy is available. Falls back to pure-Python otherwise.
"""

from __future__ import annotations

from typing import Optional

try:  # optional acceleration
    import numpy as _np  # type: ignore

    _HAS_NUMPY = True
except ImportError:  # pragma: no cover - optional
    _np = None  # type: ignore
    _HAS_NUMPY = False

_POLY_REDUCED = 0x1B  # 0x11B without the x^8 term


def gf_mul(a: int, b: int) -> int:
    res = 0
    while b:
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= _POLY_REDUCED
        b >>= 1
    return res


def gf_pow(a: int, power: int) -> int:
    result = 1
    base = a
    while power:
        if power & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        power >>= 1
    return result


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("No inverse for zero in GF(256)")
    return gf_pow(a, 254)


_NP_MUL_TABLE = None  # type: ignore


def _ensure_np_table():
    global _NP_MUL_TABLE
    if not _HAS_NUMPY:
        return
    if _NP_MUL_TABLE is not None:
        return
    # Build 256x256 table T[c, x] = gf_mul(x, c)
    tbl = _np.empty((256, 256), dtype=_np.uint8)
    for c in range(256):
        for x in range(256):
            tbl[c, x] = gf_mul(x, c)
    _NP_MUL_TABLE = tbl


def gf_mul_bytes(data: bytes, coeff: int) -> bytes:
    if coeff == 0:
        return bytes(len(data))
    if coeff == 1:
        return data
    if _HAS_NUMPY and len(data) >= 1024:
        _ensure_np_table()
        row = _NP_MUL_TABLE[coeff]  # type: ignore[index]
        arr = _np.frombuffer(data, dtype=_np.uint8)  # type: ignore[attr-defined]
        out = row[arr]
        return out.tobytes()
    return bytes(gf_mul(b, coeff) for b in data)


def gf_add_bytes(dest: bytearray, src: bytes):
    if _HAS_NUMPY and len(src) >= 1024:
        dest_mv = memoryview(dest)
        darr = _np.frombuffer(dest_mv, dtype=_np.uint8)  # type: ignore[attr-defined]
        sarr = _np.frombuffer(src, dtype=_np.uint8)  # type: ignore[attr-defined]
        n = len(sarr)
        darr[:n] ^= sarr
        return
    for i, b in enumerate(src):
        dest[i] ^= b

"""
CRC32C (Castagnoli) implementation with a precomputed table.
Pure Python fallback to avoid external dependencies.
"""

_POLY = 0x1EDC6F41


def _make_table():
    tbl = []
    for n in range(256):
        c = n
        for _ in range(8):
            if c & 1:
                c = (c >> 1) ^ _POLY
            else:
                c >>= 1
        tbl.append(c & 0xFFFFFFFF)
    return tuple(tbl)


_TABLE = _make_table()


def crc32c(data: bytes, crc: int = 0) -> int:
    c = (~crc) & 0xFFFFFFFF
    for b in data:
        c = _TABLE[(c ^ b) & 0xFF] ^ (c >> 8)
    return (~c) & 0xFFFFFFFF


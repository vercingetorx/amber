from __future__ import annotations

from typing import Optional

from .tlv import _tlv as _t, _varint_encode as _ve, _encode_str as _es


def build_entry_begin_payload(
    *,
    entry_id: int,
    kind: int,  # 0=file, 1=dir, 2=symlink
    path: str,
    mode: Optional[int] = None,
    mtime_sec: Optional[int] = None,
    mtime_nsec: Optional[int] = None,
    atime_sec: Optional[int] = None,
    atime_nsec: Optional[int] = None,
    size: Optional[int] = None,
    file_codec: Optional[int] = None,
    chunk_size: Optional[int] = None,
    symlink_target: Optional[str] = None,
) -> bytes:
    eb = bytearray()
    eb += _t(1, _ve(entry_id))
    eb += _t(2, _ve(kind))
    eb += _t(3, _es(path))
    if mode is not None:
        eb += _t(4, _ve(mode))
    if mtime_sec is not None:
        eb += _t(5, _ve(mtime_sec) + _ve(mtime_nsec or 0))
    if atime_sec is not None:
        eb += _t(6, _ve(atime_sec) + _ve(atime_nsec or 0))
    if size is not None:
        eb += _t(7, _ve(size))
    if file_codec is not None:
        eb += _t(8, _ve(file_codec))
    if chunk_size is not None:
        eb += _t(9, _ve(chunk_size))
    if kind == 2 and symlink_target is not None:
        eb += _t(10, _es(symlink_target))
    return bytes(eb)


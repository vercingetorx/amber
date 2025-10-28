from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from . import tlv
from .constants import INDEX_FRAME_MAGIC, INDEX_LOC_MAGIC
from .crc32c import crc32c
from .hashutil import blake2s_32
from .encryption import EncryptionContext


_IDX_FRAME_HDR = struct.Struct("<8sI Q 32s 32s")
_IDX_LOC_STRUCT = struct.Struct("<8sQQI16sI")


def build_anchor_payload(symbols: List[Dict], symbol_size: int, merkle_root: bytes, seed_base: Optional[bytes]) -> Dict:
    sample = symbols[-min(64, len(symbols)) :]
    payload = {
        "version": 1,
        "symbol_size": symbol_size,
        "merkle_root": merkle_root,
        **({"seed_base": seed_base} if seed_base else {}),
        "symbols": [
            {
                "symbol_index": s["symbol_index"],
                "offset": s["offset"],
                **({"record_offset": s["record_offset"]} if "record_offset" in s else {}),
                "length": s["length"],
                "tag16": s["tag16"],
                "is_parity": s.get("is_parity", False),
                **({"seed_base": s["seed_base"]} if s.get("seed_base") else {}),
            }
            for s in sample
        ],
    }
    return payload


def write_anchor_record(fh, encryptor: Optional[EncryptionContext], payload: Dict) -> int:
    from .records import write_record
    from .constants import RTYPE_ANCHOR

    off, _, _ = write_record(fh, RTYPE_ANCHOR, 0, b"", tlv.dumps_anchor(payload), encryptor=encryptor)
    return off


def write_index_trailer(
    fh,
    encryptor: Optional[EncryptionContext],
    archive_uuid: bytes,
    index_payload: bytes,
    merkle_root: bytes,
) -> None:
    import zlib

    frame_flags = 0
    compressed = zlib.compress(index_payload, level=6)
    if len(compressed) < len(index_payload):
        frame_flags |= 1
    else:
        compressed = index_payload
    if encryptor is not None:
        frame_flags |= 2

    index_hash = blake2s_32(index_payload)
    frame_plain = _IDX_FRAME_HDR.pack(INDEX_FRAME_MAGIC, frame_flags, len(index_payload), index_hash, merkle_root)
    frame_plain += compressed
    frame_crc = crc32c(frame_plain)
    frame_plain += struct.pack("<I", frame_crc)

    frame_locs = []
    for seq in (0, 1):
        frame_start = fh.tell()
        frame = encryptor.encrypt(b"IDXFRAME", frame_plain, nonce_material=struct.pack("<Q", frame_start)) if encryptor else frame_plain
        fh.write(frame)
        fh.flush()
        import os as _os
        _os.fsync(fh.fileno())
        frame_locs.append((seq, frame_start, len(frame)))
    for seq, frame_start, flen in frame_locs:
        loc_crc = crc32c(INDEX_LOC_MAGIC + struct.pack("<QQI16s", flen, frame_start, seq, archive_uuid))
        loc = _IDX_LOC_STRUCT.pack(INDEX_LOC_MAGIC, flen, frame_start, seq, archive_uuid, loc_crc)
        fh.write(loc)
    fh.flush()
    import os as _os
    _os.fsync(fh.fileno())


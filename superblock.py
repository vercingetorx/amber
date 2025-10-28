from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO

from .constants import SUPERBLOCK_MAGIC
from .crc32c import crc32c


_SUPERBLOCK_STRUCT = struct.Struct("<8sHHI16sQI I I H H16sIII III 12sI")


@dataclass
class Superblock:
    version_major: int
    version_minor: int
    flags: int
    uuid: bytes
    created_sec: int
    created_nanos: int
    default_chunk_size: int
    default_codec: int
    kdf_id: int
    kdf_salt: bytes
    argon_memory_cost: int
    argon_time_cost: int
    argon_parallelism: int


def read_superblock(f: BinaryIO) -> Superblock:
    f.seek(0)
    raw = f.read(_SUPERBLOCK_STRUCT.size)
    if len(raw) != _SUPERBLOCK_STRUCT.size:
        raise ValueError("Superblock too short")
    (magic, vmaj, vmin, flags, uuid, csec, cnanos, dchunk, dcodec, _res_u16, kdf_id, kdf_salt, _amem, _atime, _alanes, sN, sr, sp, _res12, hdr_crc) = _SUPERBLOCK_STRUCT.unpack(raw)
    if magic != SUPERBLOCK_MAGIC:
        raise ValueError("Bad superblock magic")
    if crc32c(raw[:-4]) != hdr_crc:
        raise ValueError("Superblock CRC mismatch")
    return Superblock(
        version_major=vmaj,
        version_minor=vmin,
        flags=flags,
        uuid=uuid,
        created_sec=csec,
        created_nanos=cnanos,
        default_chunk_size=dchunk,
        default_codec=dcodec,
        kdf_id=kdf_id,
        kdf_salt=kdf_salt,
        argon_memory_cost=_amem,
        argon_time_cost=_atime,
        argon_parallelism=_alanes,
    )

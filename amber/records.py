from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Optional, Tuple

from .constants import (
    REC_SYNC,
    RFLAG_HEADER_EXT,
)
from .crc32c import crc32c
from .encryption import EncryptionContext


# Record header (fixed 24 bytes)
# struct: <4s B B H Q I I
#  - sync[4]
#  - rtype u8
#  - rflags u8
#  - header_len u16 (bytes after this fixed header up to payload)
#  - payload_len u64
#  - header_crc32c u32 (over fixed header without crc, plus header_ext)
#  - reserved u32 (for future)
_REC_HDR_STRUCT = struct.Struct("<4sBBHQII")
_CHUNK_HDR_EXT_STRUCT = struct.Struct("<QIIHH16s16s")


@dataclass
class RecordHeader:
    rtype: int
    rflags: int
    header_ext: bytes
    payload_len: int

    def pack(self) -> bytes:
        header_len = len(self.header_ext)
        pre_crc = _REC_HDR_STRUCT.pack(
            REC_SYNC, self.rtype, self.rflags | (RFLAG_HEADER_EXT if header_len else 0), header_len, self.payload_len, 0, 0
        )
        crc = crc32c(pre_crc[:-8] + self.header_ext)  # exclude crc field and reserved
        return _REC_HDR_STRUCT.pack(
            REC_SYNC, self.rtype, self.rflags | (RFLAG_HEADER_EXT if header_len else 0), header_len, self.payload_len, crc, 0
        ) + self.header_ext


def write_record(
    f: BinaryIO,
    rtype: int,
    rflags: int,
    header_ext: bytes,
    payload: bytes,
    encryptor: Optional[EncryptionContext] = None,
) -> Tuple[int, int, bytes]:
    payload_len = len(payload)
    if encryptor is not None:
        payload_len += encryptor.overhead()
    hdr_bytes = RecordHeader(rtype=rtype, rflags=rflags, header_ext=header_ext, payload_len=payload_len).pack()
    off = f.tell()
    final_payload = (
        payload
        if encryptor is None
        else encryptor.encrypt(hdr_bytes, payload, nonce_material=struct.pack("<Q", off))
    )
    f.write(hdr_bytes)
    payload_offset = f.tell()
    f.write(final_payload)
    return off, payload_offset, final_payload


def read_exact(f: BinaryIO, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n:
        raise EOFError("Unexpected EOF")
    return b


def read_record_at(f: BinaryIO, offset: int, decryptor: Optional[EncryptionContext] = None):
    f.seek(offset)
    return read_record(f, decryptor=decryptor)


def read_record(f: BinaryIO, decryptor: Optional[EncryptionContext] = None):
    # Read fixed header
    fixed = read_exact(f, _REC_HDR_STRUCT.size)
    sync, rtype, rflags, header_len, payload_len, hdr_crc, _reserved = _REC_HDR_STRUCT.unpack(fixed)
    if sync != REC_SYNC:
        raise ValueError("Bad record sync")
    header_ext = read_exact(f, header_len) if header_len else b""
    calc_crc = crc32c(fixed[:-8] + header_ext)
    if calc_crc != hdr_crc:
        raise ValueError("Record header CRC32C mismatch")
    payload = read_exact(f, payload_len)
    header_bytes = fixed + header_ext
    if decryptor is not None:
        payload = decryptor.decrypt(header_bytes, payload)
    return rtype, rflags, header_ext, payload


def build_chunk_header_ext(
    entry_id: int,
    chunk_index: int,
    uncompressed_len: int,
    codec_id: int,
    tag16: bytes,
    *,
    aux16: bytes = b"\x00" * 16,
    flags: int = 0,
) -> bytes:
    if len(tag16) != 16:
        raise ValueError("tag16 must be 16 bytes")
    if len(aux16) != 16:
        raise ValueError("aux16 must be 16 bytes")
    return _CHUNK_HDR_EXT_STRUCT.pack(entry_id, chunk_index, uncompressed_len, codec_id, flags, tag16, aux16)


def parse_chunk_header_ext(header_ext: bytes) -> Tuple[int, int, int, int, int, bytes, bytes]:
    """
    Returns: (entry_id, chunk_index, uncompressed_len, codec_id, flags, tag16, aux16)
    """
    if len(header_ext) < _CHUNK_HDR_EXT_STRUCT.size:
        raise ValueError("chunk header_ext too short")
    entry_id, chunk_index, uncompressed_len, codec_id, flags, tag16, aux16 = _CHUNK_HDR_EXT_STRUCT.unpack(
        header_ext[: _CHUNK_HDR_EXT_STRUCT.size]
    )
    return entry_id, chunk_index, uncompressed_len, codec_id, flags, tag16, aux16

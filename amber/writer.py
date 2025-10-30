from __future__ import annotations

import io
import os
import stat
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Tuple

from .constants import (
    SUPERBLOCK_MAGIC,
    VERSION_MAJOR,
    VERSION_MINOR,
    FLAG_ENCRYPTED,
    FLAG_ECC_PRESENT,
    FLAG_CHUNK_COMPRESS_DEFAULT,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_CODEC_ID,
    CODEC_NONE,
    CODEC_RX_PARITY,
    RTYPE_ENTRY_BEGIN,
    RTYPE_CHUNK,
    RTYPE_ENTRY_END,
    RFLAG_CHUNK_TAG_PRESENT,
    RFLAG_PARITY_RECORD,
)
from .crc32c import crc32c
from .hashutil import blake2s_16, blake2s_32, merkle_leaf_from_chunk_tag, merkle_parent
from .records import write_record, build_chunk_header_ext
from .codec import Codec
from .constants import new_uuid_bytes
from .gf256 import gf_mul_bytes, gf_add_bytes
from .encryption import EncryptionContext, EncryptionParams
from .pathutil import norm_path
from .chunkemit import ChunkEmitContext, emit_file_chunks


_SUPERBLOCK_STRUCT = struct.Struct("<8sHHI16sQI I I H H16sIII III 12sI")
# The above layout is a pragmatic packing for the POC; not a strict match to the spec.
# Fields (little endian):
# magic[8], ver_major u16, ver_minor u16, flags u32,
# uuid[16], created_sec u64, created_nanos u32,
# default_chunk_size u32, default_codec u16, reserved_u16,
# kdf_id u16, kdf_salt[16], argon_mem u32, argon_time u32, argon_lanes u32,
# reserved u32 x3
# reserved[12], header_crc32c u32


def _pack_superblock(
    flags: int,
    archive_uuid: bytes,
    default_chunk_size: int,
    default_codec: int,
    enc_params: Optional[EncryptionParams],
) -> bytes:
    created_sec = int(time.time())
    created_nanos = 0
    if enc_params is not None:
        kdf_id = 1  # Argon2id
        salt = enc_params.salt
        argon_mem = enc_params.memory_cost_kib
        argon_time = enc_params.time_cost
        argon_lanes = enc_params.parallelism
    else:
        kdf_id = 0
        salt = b"\x00" * 16
        argon_mem = 0
        argon_time = 0
        argon_lanes = 0
    pre = _SUPERBLOCK_STRUCT.pack(
        SUPERBLOCK_MAGIC,
        VERSION_MAJOR,
        VERSION_MINOR,
        flags,
        archive_uuid,
        created_sec,
        created_nanos,
        default_chunk_size,
        default_codec,
        0,  # reserved_u16
        kdf_id,
        salt,
        argon_mem,
        argon_time,
        argon_lanes,
        0,
        0,
        0,
        b"\x00" * 12,
        0,  # crc placeholder
    )
    crc = crc32c(pre[:-4])
    return pre[:-4] + struct.pack("<I", crc)


_IDX_FRAME_HDR = struct.Struct("<8sI Q 32s 32s")
_IDX_LOC_STRUCT = struct.Struct("<8sQQI16sI")


@dataclass
class ChunkDesc:
    offset: int
    payload_offset: int
    payload_len: int
    uncompressed_len: int
    chunk_index: int
    tag16: bytes


@dataclass
class Entry:
    entry_id: int
    kind: int  # 0=file, 1=dir, 2=symlink
    path: str
    size: int = 0
    mode: Optional[int] = None
    mtime_sec: Optional[int] = None
    mtime_nsec: Optional[int] = None
    atime_sec: Optional[int] = None
    atime_nsec: Optional[int] = None
    file_codec: Optional[int] = None
    chunk_size: Optional[int] = None
    chunks: List[ChunkDesc] = field(default_factory=list)
    file_hash32: Optional[bytes] = None
    symlink_target: Optional[str] = None

@dataclass
class SymbolInfo:
    symbol_index: int
    offset: int
    record_offset: int
    length: int
    tag16: bytes
    stripe_index: int
    is_parity: bool
    seed_base: Optional[bytes] = None


@dataclass
class StripeInfo:
    stripe_index: int
    data_symbols: List[int]
    parity_symbol: int


@dataclass
class RXParityInfo:
    symbol_index: int
    seed_id: int
    offset: int
    length: int
    tag16: bytes
    seed_base: bytes


class ArchiveWriter:
    """Streaming writer that produces fully authenticated Amber archives."""
    def __init__(
        self,
        out_path: str,
        default_chunk_size: int = DEFAULT_CHUNK_SIZE,
        default_codec: int = DEFAULT_CODEC_ID,
        password: Optional[str] = None,
        ecc_profile: Optional[str] = None,
        lrp_enabled: Optional[bool] = None,
        lrp_k: Optional[int] = None,
        rx_epsilon_ppm: Optional[int] = None,
        anchor_interval_bytes: Optional[int] = 64 * 1024 * 1024,
    ):
        self.out_path = out_path
        self.f: Optional[BinaryIO] = None
        self.flags = 0
        if default_codec != CODEC_NONE:
            self.flags |= FLAG_CHUNK_COMPRESS_DEFAULT
        self.encryptor: Optional[EncryptionContext] = None
        if password:
            self.encryptor = EncryptionContext.create(password)
            self.flags |= FLAG_ENCRYPTED
        self.flags |= FLAG_ECC_PRESENT
        self.default_chunk_size = default_chunk_size
        self.default_codec = default_codec
        self.archive_uuid = new_uuid_bytes()
        self.entries: List[Entry] = []
        self._next_entry_id = 1
        # ECC tracking
        self.symbols: List[SymbolInfo] = []
        self.stripes: List[StripeInfo] = []
        self.symbol_size = 65536
        self.lrp_enabled = True
        self.lrp_k = 16
        self._next_stripe_index = 0
        self.symbol_data: Dict[int, bytes] = {}
        self.rx_seed_base = os.urandom(16)
        # ECC configuration (defaults to 'balanced')
        # Profiles: lean -> no LRP, RX≈4; balanced -> LRP 1/16 + RX 11%; archival -> LRP 1/12 + RX 17%
        profile = (ecc_profile or "balanced").lower()
        if profile == "lean":
            self.lrp_enabled = False if lrp_enabled is None else lrp_enabled
            if lrp_k is not None:
                self.lrp_k = lrp_k
            self.rx_epsilon_ppm = 40000 if rx_epsilon_ppm is None else rx_epsilon_ppm
        elif profile == "archival":
            self.lrp_enabled = True if lrp_enabled is None else lrp_enabled
            self.lrp_k = 12 if lrp_k is None else lrp_k
            self.rx_epsilon_ppm = 170000 if rx_epsilon_ppm is None else rx_epsilon_ppm
        else:  # balanced (default)
            if lrp_enabled is not None:
                self.lrp_enabled = lrp_enabled
            if lrp_k is not None:
                self.lrp_k = lrp_k
            self.rx_epsilon_ppm = 110000 if rx_epsilon_ppm is None else rx_epsilon_ppm
        self.rx_parities: List[RXParityInfo] = []
        self.anchors: List[Dict[str, int]] = []
        # Periodic anchors
        self.anchor_interval_bytes = anchor_interval_bytes or 0
        self._bytes_since_anchor = 0
        # Shared chunk emission context (spans files to avoid per-file tail stripes)
        self._chunk_ctx: Optional[ChunkEmitContext] = None
        self._lrp_pending_data: List[int] = []

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def open(self):
        if self.f is not None:
            return
        self.f = open(self.out_path, "wb")
        enc_params = self.encryptor.export_params() if self.encryptor else None
        sb = _pack_superblock(
            flags=self.flags,
            archive_uuid=self.archive_uuid,
            default_chunk_size=self.default_chunk_size,
            default_codec=self.default_codec,
            enc_params=enc_params,
        )
        self.f.write(sb)

    def close(self):
        if self.f is not None:
            self.f.close()
            self.f = None

    def add_dir(
        self,
        arc_path: str,
        mode: Optional[int] = None,
        *,
        mtime_sec: Optional[int] = None,
        mtime_nsec: Optional[int] = None,
        atime_sec: Optional[int] = None,
        atime_nsec: Optional[int] = None,
    ):
        """Record a directory entry to preserve hierarchy and metadata."""
        e = Entry(entry_id=self._alloc_id(), kind=1, path=norm_path(arc_path), mode=mode)
        if mtime_sec is not None:
            e.mtime_sec = int(mtime_sec)
            e.mtime_nsec = int(mtime_nsec or 0)
        else:
            e.mtime_sec = None
            e.mtime_nsec = None
        if atime_sec is not None:
            e.atime_sec = int(atime_sec)
            e.atime_nsec = int(atime_nsec or 0)
        else:
            e.atime_sec = None
            e.atime_nsec = None
        self._write_entry_begin(e)
        self._write_entry_end(e)
        self.entries.append(e)

    def add_symlink(self, arc_path: str, target: str):
        """Record a symbolic link pointing to ``target``."""
        e = Entry(entry_id=self._alloc_id(), kind=2, path=norm_path(arc_path), symlink_target=target)
        self._write_entry_begin(e)
        self._write_entry_end(e)
        self.entries.append(e)

    def add_file(self, arc_path: str, fs_path: str, codec_id: Optional[int] = None, chunk_size: Optional[int] = None, mode: Optional[int] = None):
        """Stream a filesystem file into the archive, chunking and hashing on the fly."""
        if self.f is None:
            raise RuntimeError("Archive not open")
        arc_path = norm_path(arc_path)
        cs = chunk_size or self.default_chunk_size
        codec = codec_id if codec_id is not None else self.default_codec
        st = os.stat(fs_path, follow_symlinks=True)
        from os.path import getsize, getmtime, getatime
        e = Entry(
            entry_id=self._alloc_id(),
            kind=0,
            path=arc_path,
            size=getsize(fs_path),
            mode=(st.st_mode & 0o7777) if mode is None else mode,
            mtime_sec=int(getmtime(fs_path)),
            mtime_nsec=0,
            atime_sec=int(getatime(fs_path)),
            atime_nsec=0,
            file_codec=codec,
            chunk_size=cs,
        )
        self._write_entry_begin(e)
        # Ensure shared chunk emission context exists and spans files
        if self._chunk_ctx is None:
            def _symbol_append(sym_index: int, record_offset: int, payload_offset: int, length: int, tag16: bytes, is_parity: bool, stripe_index: int, data_bytes: bytes):
                info = SymbolInfo(
                    symbol_index=sym_index,
                    offset=payload_offset,
                    record_offset=record_offset,
                    length=length,
                    tag16=tag16,
                    stripe_index=(-1 if not is_parity else stripe_index),
                    is_parity=is_parity,
                    seed_base=None,
                )
                self.symbols.append(info)
                self.symbol_data[sym_index] = data_bytes
                if not is_parity:
                    self._lrp_pending_data.append(sym_index)
                    # Periodic anchor tracking on data symbols only
                    if self.anchor_interval_bytes:
                        self._bytes_since_anchor += length
                        if self._bytes_since_anchor >= self.anchor_interval_bytes:
                            try:
                                mr = self._compute_merkle_root()
                                self._write_anchor(mr)
                            finally:
                                self._bytes_since_anchor = 0
                else:
                    # Close a stripe over the pending data symbols
                    for di in self._lrp_pending_data:
                        # Update their stripe index
                        self.symbols[di].stripe_index = stripe_index
                    stripe = StripeInfo(stripe_index=stripe_index, data_symbols=self._lrp_pending_data.copy(), parity_symbol=sym_index)
                    self.stripes.append(stripe)
                    self._lrp_pending_data.clear()

            self._chunk_ctx = ChunkEmitContext(
                fh=self.f,
                encryptor=self.encryptor,
                symbol_size=self.symbol_size,
                lrp_enabled=self.lrp_enabled,
                lrp_k=self.lrp_k,
                next_symbol_index=len(self.symbols),
                next_stripe_index=self._next_stripe_index,
                symbol_append=_symbol_append,
                on_data_symbol=None,
            )

        chunks_dicts, file_hash32 = emit_file_chunks(
            self._chunk_ctx,
            entry_id=e.entry_id,
            fs_path=fs_path,
            codec_id=codec,
            chunk_size=cs,
        )
        # Do not flush LRP here; keep spanning files. We'll finalize later.
        # Assign chunks to entry
        e.chunks = [
            ChunkDesc(
                offset=c["offset"],
                payload_offset=c["payload_offset"],
                payload_len=c["payload_len"],
                uncompressed_len=c["uncompressed_len"],
                chunk_index=c["chunk_index"],
                tag16=c["blake2s_16"],
            )
            for c in chunks_dicts
        ]
        # file hash
        e.file_hash32 = file_hash32
        self._write_entry_end(e, total_chunks=len(e.chunks))
        self.entries.append(e)

    def finalize(self):
        """
        Completes the archive writing process.

        This method performs several critical steps to ensure the archive is
        valid and self-contained:
        1.  Flushes any pending LRP stripes.
        2.  Generates and writes all RX parity symbols.
        3.  Computes the final Merkle root over all data chunks.
        4.  Writes a final anchor record.
        5.  Builds and writes the main index, which contains all metadata
            needed to read the archive.
        """
        if self.f is None:
            raise RuntimeError("Archive not open")
        # Flush pending ECC stripes (via shared chunk context)
        if self._chunk_ctx is not None:
            self._chunk_ctx.finalize()
            self._next_stripe_index = self._chunk_ctx.next_stripe_index
        # Generate RX parity symbols
        self._generate_rx_parity()
        merkle_root = self._compute_merkle_root()
        # Anchor record for recovery and trailer via shared helpers
        from .trailer import build_anchor_payload, write_anchor_record, write_index_trailer
        # Build symbol dicts for anchor payload
        symbol_dicts = [
            {
                "symbol_index": s.symbol_index,
                "offset": s.offset,
                "record_offset": s.record_offset,
                "length": s.length,
                "tag16": s.tag16,
                "is_parity": s.is_parity,
                **({"seed_base": s.seed_base} if s.seed_base else {}),
            }
            for s in self.symbols
        ]
        anchor_payload = build_anchor_payload(symbol_dicts, self.symbol_size, merkle_root, self.rx_seed_base)
        off = write_anchor_record(self.f, self.encryptor, anchor_payload)
        self.anchors.append({
            "offset": off,
            "symbol_count": min(64, len(self.symbols)),
            "first_symbol": self.symbols[-min(64, len(self.symbols))].symbol_index if self.symbols else 0,
            "last_symbol": self.symbols[-1].symbol_index if self.symbols else 0,
        })
        # Build index
        idx_payload = self._build_index_payload()
        write_index_trailer(self.f, self.encryptor, self.archive_uuid, idx_payload, merkle_root)

    # internals
    def _alloc_id(self) -> int:
        i = self._next_entry_id
        self._next_entry_id += 1
        return i

    def _write_entry_begin(self, e: Entry):
        if self.f is None:
            raise RuntimeError("Archive not open")
        from .entryutil import build_entry_begin_payload
        payload = build_entry_begin_payload(
            entry_id=e.entry_id,
            kind=e.kind,
            path=e.path,
            mode=e.mode,
            mtime_sec=e.mtime_sec,
            mtime_nsec=e.mtime_nsec,
            atime_sec=e.atime_sec,
            atime_nsec=e.atime_nsec,
            size=e.size or None,
            file_codec=e.file_codec,
            chunk_size=e.chunk_size,
            symlink_target=e.symlink_target,
        )
        write_record(self.f, RTYPE_ENTRY_BEGIN, 0, b"", payload, encryptor=self.encryptor)

    def _write_entry_end(self, e: Entry, total_chunks: int = 0):
        if self.f is None:
            raise RuntimeError("Archive not open")
        # header ext: entry_id u64, total_chunk_count u32
        hdr_ext = struct.pack("<QI", e.entry_id, total_chunks)
        write_record(self.f, RTYPE_ENTRY_END, 0, hdr_ext, b"", encryptor=self.encryptor)

    # Legacy LRP helpers removed; LRP emission is centralized in chunkemit.

    def _generate_rx_parity(self):
        """
        Generates and writes RX parity symbols for the current ECC group.

        The number of parity symbols is determined by the `rx_epsilon_ppm`
        parameter, which specifies the desired overhead in parts per million.
        Each parity symbol is a random linear combination of the data symbols,
        generated deterministically from a seed.
        """
        # Use stable ordering of data indices to match decoder
        data_indices = sorted([info.symbol_index for info in self.symbols if not info.is_parity])
        if not data_indices:
            return
        n = len(data_indices)
        base = n * self.rx_epsilon_ppm // 1_000_000
        target = max(2 if n >= 2 else 1, base)
        start_seed = len(self.rx_parities)
        for _ in range(target):
            seed_id = len(self.rx_parities)
            from .rx import sample_rx_combination
            combo = sample_rx_combination(self.rx_seed_base, seed_id, data_indices)
            payload = self._compute_rx_payload(combo)
            tag16 = blake2s_16(payload)
            hdr_ext = build_chunk_header_ext(0, seed_id, self.symbol_size, CODEC_RX_PARITY, tag16, aux16=self.rx_seed_base)
            rflags = RFLAG_CHUNK_TAG_PRESENT | RFLAG_PARITY_RECORD
            parity_encryptor = self.encryptor
            off, payload_offset, final_payload = write_record(
                self.f, RTYPE_CHUNK, rflags, hdr_ext, payload, encryptor=parity_encryptor
            )
            symbol_index = len(self.symbols)
            info = SymbolInfo(
                symbol_index=symbol_index,
                offset=payload_offset,
                record_offset=off,
                length=len(final_payload),
                tag16=tag16,
                stripe_index=-1,
                is_parity=True,
                seed_base=self.rx_seed_base,
            )
            self.symbols.append(info)
            self.symbol_data[symbol_index] = final_payload
            parity_info = RXParityInfo(
                symbol_index=symbol_index,
                seed_id=seed_id,
                offset=payload_offset,
                length=len(final_payload),
                tag16=tag16,
                seed_base=self.rx_seed_base,
            )
            self.rx_parities.append(parity_info)

    # Note: RX sampling is centralized in amber.rx.sample_rx_combination

    def _compute_rx_payload(self, combo: List[Tuple[int, int]]) -> bytes:
        parity = bytearray(self.symbol_size)
        for sym_index, coeff in combo:
            data = self._get_symbol_data(sym_index)
            scaled = gf_mul_bytes(data, coeff)
            gf_add_bytes(parity, scaled)
        return bytes(parity)

    def _get_symbol_data(self, symbol_index: int) -> bytes:
        data = self.symbol_data.get(symbol_index)
        if data is None:
            raise RuntimeError(f"Missing symbol data for index {symbol_index}")
        if len(data) == self.symbol_size:
            return data
        buf = bytearray(self.symbol_size)
        buf[: len(data)] = data
        return bytes(buf)

    def _write_anchor(self, merkle_root: bytes):
        if self.f is None:
            raise RuntimeError("Archive not open")
        from .trailer import build_anchor_payload, write_anchor_record
        symbol_dicts = [
            {
                "symbol_index": info.symbol_index,
                "offset": info.offset,
                "record_offset": info.record_offset,
                "length": info.length,
                "tag16": info.tag16,
                "is_parity": info.is_parity,
                **({"seed_base": info.seed_base} if info.seed_base else {}),
            }
            for info in self.symbols
        ]
        payload = build_anchor_payload(symbol_dicts, self.symbol_size, merkle_root, self.rx_seed_base)
        off = write_anchor_record(self.f, self.encryptor, payload)
        count = min(64, len(self.symbols))
        first = self.symbols[-count].symbol_index if count else 0
        last = self.symbols[-1].symbol_index if count else 0
        self.anchors.append({
            "offset": off,
            "symbol_count": count,
            "first_symbol": first,
            "last_symbol": last,
        })

    def _compute_merkle_root(self) -> bytes:
        """
        Computes the archive-wide Merkle root from the tags of all data chunks.

        The Merkle tree provides a single, verifiable hash for the entire
        archive's data content. It's constructed as a binary tree, with a
        "promote" rule for odd numbers of nodes at each level.
        """
        # Flatten all chunk tags in file order
        leaves: List[bytes] = []
        for e in self.entries:
            if e.kind != 0:
                continue
            for ch in e.chunks:
                leaves.append(merkle_leaf_from_chunk_tag(ch.tag16))
        if not leaves:
            return b"\x00" * 32
        # Build binary tree with promote rule
        level = leaves
        while len(level) > 1:
            nxt: List[bytes] = []
            it = iter(level)
            for left in it:
                try:
                    right = next(it)
                except StopIteration:
                    nxt.append(left)  # promote
                    break
                nxt.append(merkle_parent(left, right))
            level = nxt
        return level[0]

    def _build_index_payload(self) -> bytes:
        """
        Constructs the main index for the archive.

        The index is a comprehensive data structure that contains all the
        metadata required to read the archive, including file and directory
        entries, chunk locations, ECC information, and anchors. It's
        serialized to a compact binary format (TLV) before being written
        to the trailer.
        """
        # Assemble index map (Python dict)
        entries = []
        for e in self.entries:
            ent = {
                "entry_id": e.entry_id,
                "kind": e.kind,
                "path": e.path,
            }
            if e.mode is not None:
                ent["mode"] = e.mode
            if e.mtime_sec is not None:
                ent["mtime"] = {"sec": e.mtime_sec, "nsec": e.mtime_nsec or 0}
            if e.atime_sec is not None:
                ent["atime"] = {"sec": e.atime_sec, "nsec": e.atime_nsec or 0}
            if e.kind == 0:
                ent["size"] = e.size
                ent["file_codec"] = e.file_codec
                ent["chunk_size"] = e.chunk_size
                ent["chunks"] = [
                    {
                        "offset": ch.offset,
                        "payload_offset": ch.payload_offset,
                        "payload_len": ch.payload_len,
                        "uncompressed_len": ch.uncompressed_len,
                        "chunk_index": ch.chunk_index,
                        "blake2s_16": ch.tag16,
                    }
                    for ch in e.chunks
                ]
                if e.file_hash32 is not None:
                    ent["file_blake2s_32"] = e.file_hash32
            if e.kind == 2 and e.symlink_target is not None:
                ent["symlink_target"] = e.symlink_target
            entries.append(ent)
        idx_map = {
            "version": {"major": VERSION_MAJOR, "minor": VERSION_MINOR},
            "archive_uuid": self.archive_uuid,
            "writer_info": "amber-poc",
            "default_chunk_size": self.default_chunk_size,
            "default_codec": self.default_codec,
            "entries": entries,
            "ecc_groups": self._build_ecc_groups(),
            "anchors": self.anchors,
            # merkle root duplicated in frame header too
        }
        from .tlv import dumps_index
        return dumps_index(idx_map)

    def _build_ecc_groups(self):
        if not self.symbols:
            return []
        symbols = []
        for info in self.symbols:
            symbols.append(
                {
                    "symbol_index": info.symbol_index,
                    "offset": info.offset,
                    "record_offset": info.record_offset,
                    "length": info.length,
                    "tag16": info.tag16,
                    "stripe_index": info.stripe_index,
                    "is_parity": info.is_parity,
                    **({"seed_base": info.seed_base} if info.seed_base else {}),
                }
            )
        stripes = []
        for stripe in self.stripes:
            stripes.append(
                {
                    "stripe_index": stripe.stripe_index,
                    "data_symbols": stripe.data_symbols,
                    "parity_symbol": stripe.parity_symbol,
                }
            )
        rx = {
            "seed_base": self.rx_seed_base,
            "epsilon_ppm": self.rx_epsilon_ppm,
            "parity": [
                {
                    "symbol_index": p.symbol_index,
                    "seed_id": p.seed_id,
                    "offset": p.offset,
                    "length": p.length,
                    "tag16": p.tag16,
                    "seed_base": self.rx_seed_base,
                }
                for p in self.rx_parities
            ],
        }
        return [
            {
                "group_id": 1,
                "symbol_size": self.symbol_size,
                "lrp": ({"k": self.lrp_k, "p": 1} if self.lrp_enabled else {"k": 0, "p": 0}),
            "rx": rx,
                "symbols": symbols,
                "stripes": stripes,
            }
        ]


 

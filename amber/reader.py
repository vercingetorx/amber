from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Dict, List, Optional

from . import tlv

from .constants import (
    INDEX_FRAME_MAGIC,
    INDEX_LOC_MAGIC,
    RTYPE_CHUNK,
    RTYPE_ANCHOR,
    CODEC_RX_PARITY,
    FLAG_ENCRYPTED,
)
from .records import read_record_at, parse_chunk_header_ext
from .codec import Codec
from .constants import CODEC_NONE, CODEC_ZSTD
from .hashutil import blake2s_16, blake2s_32, merkle_leaf_from_chunk_tag, merkle_parent
from .superblock import read_superblock, Superblock
from .crc32c import crc32c
from .errors import (
    AmberError,
    IndexLocatorError,
    IndexFrameError,
    IndexSizeError,
    IndexLengthMismatch,
    IndexHashMismatch,
    MerkleMismatch,
    EncryptedIndexRequiresPassword,
    ChunkBoundsError,
    SymbolBoundsError,
    DuplicateSymbolIndexError,
    SymbolIndexGapError,
    SymbolSizeMismatchError,
)
from .gf256 import gf_mul_bytes, gf_add_bytes, gf_inv
from .encryption import EncryptionContext, EncryptionParams


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
    kind: int
    path: str
    size: int = 0
    mode: int = 0
    mtime_sec: int = 0
    mtime_nsec: int = 0
    atime_sec: int = 0
    atime_nsec: int = 0
    file_codec: int = CODEC_NONE
    chunk_size: int = 0
    chunks: List[ChunkDesc] = None  # type: ignore
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


class ArchiveReader:
    def __init__(self, path: str, password: Optional[str] = None):
        self.path = path
        self.f: Optional[BinaryIO] = None
        self.index: Optional[Dict] = None
        self.entries: List[Entry] = []
        self.index_merkle_root: Optional[bytes] = None
        self.symbols: List[SymbolInfo] = []
        self.stripes: List[StripeInfo] = []
        self.symbol_size: int = 65536
        self.rx_seed_base: bytes = b""
        self.rx_epsilon_ppm: int = 0
        self.rx_parities: List[RXParityInfo] = []
        self.anchors_meta: List[Dict] = []
        self.anchors_data: List[Dict] = []
        self.index_frame_offset: int = 0
        self.index_locator_offset: int = 0
        self.index_region_start: int = 0
        self.index_frame_len: int = 0
        self.password = password
        self.decryptor: Optional[EncryptionContext] = None
        self.superblock: Optional[Superblock] = None
        # Anchor load diagnostics (not critical for basic operations)
        self.anchor_total_count: int = 0
        self.anchor_fail_count: int = 0

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def open(self):
        if self.f is not None:
            return
        self.f = open(self.path, "rb")
        try:
            # Parse and sanity-check superblock
            self.superblock = read_superblock(self.f)
            if self.superblock.flags & FLAG_ENCRYPTED:
                if not self.password:
                    raise ValueError("Archive is encrypted; password required")
                if self.superblock.kdf_id != 1:
                    raise ValueError("Unsupported KDF for encrypted archive")
                params = EncryptionParams(
                    salt=self.superblock.kdf_salt,
                    time_cost=self.superblock.argon_time_cost,
                    memory_cost_kib=self.superblock.argon_memory_cost,
                    parallelism=self.superblock.argon_parallelism,
                )
                self.decryptor = EncryptionContext.from_params(self.password, params)
            else:
                self.decryptor = None
            self._load_index()
        except (AmberError, OSError, ValueError, RuntimeError) as exc:
            # Ensure file handle is closed on failure to avoid leaks
            self.close()
            raise exc

    def close(self):
        if self.f is not None:
            self.f.close()
            self.f = None

    def list(self) -> List[Entry]:
        return self.entries

    def extract(self, entry: Entry, out_path: str):
        if self.f is None:
            raise RuntimeError("Archive not open")
        if entry.kind != 0:
            return
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        # codec from chunk header; fallback to entry.file_codec
        with open(out_path, "wb") as wf:
            for ch in entry.chunks:
                # Read the record at offset, skip header to payload
                rtype, rflags, hdr_ext, payload = read_record_at(self.f, ch.offset, decryptor=self.decryptor)
                if rtype != RTYPE_CHUNK:
                    raise ValueError("Expected chunk record")
                _eid, _idx, ulen, codec_id, _flags, tag16, _aux = parse_chunk_header_ext(hdr_ext)
                codec = Codec(codec_id)
                raw = codec.decompress(payload)
                if len(raw) != ch.uncompressed_len:
                    raise ValueError("Chunk length mismatch after decompress")
                # Verify tag
                if blake2s_16(raw) != tag16:
                    raise ValueError("Chunk tag mismatch; data corrupted")
                wf.write(raw)

    def verify(self) -> bool:
        """
        Performs a comprehensive integrity check of the archive.

        This method validates the archive at multiple levels:
        1.  **Chunk Tags:** Verifies the integrity of each individual data chunk.
        2.  **File Hashes:** Reconstructs the full hash of each file and compares
            it against the stored hash in the index.
        3.  **Merkle Root:** Recalculates the archive-wide Merkle root from the
            chunk tags and compares it against the root stored in the index.

        Returns:
            True if all checks pass, False otherwise.
        """
        if self.f is None:
            raise RuntimeError("Archive not open")
        ok = True
        # The index hash is checked during `_load_index`. This method focuses on
        # content verification.
        for e in self.entries:
            if e.kind != 0:
                continue
            import hashlib

            hasher = hashlib.blake2s()
            for ch in e.chunks:
                rtype, rflags, hdr_ext, payload = read_record_at(self.f, ch.offset, decryptor=self.decryptor)
                _eid, _idx, ulen, codec_id, _flags, tag16, _aux = parse_chunk_header_ext(hdr_ext)
                codec = Codec(codec_id)
                raw = codec.decompress(payload)
                # Chunk tag check
                if blake2s_16(raw) != tag16:
                    ok = False
                hasher.update(raw)
            digest = hasher.digest()
            if e.file_hash32 and digest != e.file_hash32:
                ok = False
        # Verify archive Merkle root from index chunk tags
        calc = self._compute_merkle_from_index()
        if self.index_merkle_root and calc != self.index_merkle_root:
            ok = False
        return ok

    # internals
    def _load_index(self):
        """
        Finds and loads the archive index from the end of the file.

        This function implements a robust mechanism to locate the index, which
        is crucial for reading the archive. The process involves:
        1.  Reading a tail buffer from the end of the file.
        2.  Scanning backwards through the buffer to find the `INDEX_LOC_MAGIC`.
        3.  Validating the locator's CRC and UUID to ensure it's a valid pointer.
        4.  Handling the redundant index frames to find the start of the entire
            index region.
        5.  Performing security checks, such as a bounds check on the
            uncompressed index size to prevent decompression bombs.
        """
        assert self.f is not None
        # Read last 128 KiB and search backward for the latest valid locator (CRC-checked)
        st = os.fstat(self.f.fileno())
        size = st.st_size
        tail_size = min(128 * 1024, size)
        self.f.seek(size - tail_size)
        tail = self.f.read(tail_size)
        magic = INDEX_LOC_MAGIC
        scan_pos = len(tail)
        loc_off = -1
        frame_len = 0
        copy_seq = 0
        frame_off = 0
        archive_uuid = self.superblock.uuid if self.superblock else b"\x00" * 16
        while True:
            scan_pos = tail.rfind(magic, 0, scan_pos)
            if scan_pos == -1:
                break
            candidate_off = size - tail_size + scan_pos
            self.f.seek(candidate_off)
            loc_raw = self.f.read(_IDX_LOC_STRUCT.size)
            if len(loc_raw) != _IDX_LOC_STRUCT.size:
                scan_pos -= 1
                continue
            loc_magic, fl, foff, seq, loc_uuid, loc_crc = _IDX_LOC_STRUCT.unpack(loc_raw)
            if loc_magic != INDEX_LOC_MAGIC:
                scan_pos -= 1
                continue
            # CRC over magic + (flen, foff, seq, uuid)
            exp_crc = crc32c(INDEX_LOC_MAGIC + struct.pack("<QQI16s", fl, foff, seq, loc_uuid))
            if exp_crc != loc_crc:
                scan_pos -= 1
                continue
            # Bind to this archive by UUID
            if archive_uuid and loc_uuid != archive_uuid:
                scan_pos -= 1
                continue
            loc_off = candidate_off
            frame_len = fl
            copy_seq = seq
            frame_off = foff
            break
        if loc_off < 0:
            raise IndexLocatorError("Index locator not found or CRC mismatch")
        # Read frame using recorded frame offset
        self.f.seek(frame_off)
        frame_body = self.f.read(frame_len)
        self.index_frame_offset = frame_off
        self.index_locator_offset = loc_off
        self.index_frame_len = frame_len
        # Determine the start of the trailing index region.
        # Writer appends two identical frames back-to-back followed by two locators.
        # The last locator (seq==1) points to the second frame; the first (seq==0) points to the first frame.
        # To safely remove the entire trailing index region during append, we need the start of the first frame.
        # If the locator we found has seq==1, the first frame starts at (frame_off - frame_len).
        # If seq==0, frame_off already points at the first frame.
        first_frame_off = frame_off - frame_len if copy_seq == 1 else frame_off
        if first_frame_off < 0:
            first_frame_off = 0
        self.index_region_start = first_frame_off
        if self.decryptor is not None:
            frame_plain = self.decryptor.decrypt(b"IDXFRAME", frame_body)
        else:
            frame_plain = frame_body
        if len(frame_plain) < 4:
            raise ValueError("Index frame too short")
        frame_crc = struct.unpack("<I", frame_plain[-4:])[0]
        if crc32c(frame_plain[:-4]) != frame_crc:
            raise ValueError("Index frame CRC mismatch")
        hdr = frame_plain[: _IDX_FRAME_HDR.size]
        frame_magic, frame_flags, uncompressed_len, index_hash, merkle_root = _IDX_FRAME_HDR.unpack(hdr)
        if frame_magic != INDEX_FRAME_MAGIC:
            raise IndexFrameError("Bad index frame magic")
        if self.decryptor is None and (frame_flags & 2):
            raise EncryptedIndexRequiresPassword("Encrypted index frame requires password")
        # Bounds-check uncompressed length to avoid decompress bombs
        MAX_INDEX_UNCOMPRESSED = 128 * 1024 * 1024  # 128 MiB default safety bound
        if uncompressed_len > MAX_INDEX_UNCOMPRESSED:
            raise IndexSizeError("Index size exceeds safety bound")
        payload = frame_plain[_IDX_FRAME_HDR.size : -4]
        # Decompress if needed
        if frame_flags & 1:
            import zlib

            payload = zlib.decompress(payload)
        if len(payload) != uncompressed_len:
            raise IndexLengthMismatch("Index uncompressed length mismatch")
        if blake2s_32(payload) != index_hash:
            raise IndexHashMismatch("Index hash mismatch")
        idx = tlv.loads_index(
            payload,
            limits={
                "max_entries": 1_000_000,
                "max_total_chunks": 5_000_000,
                "max_symbols": 5_000_000,
                "max_rx_parity": 5_000_000,
                "max_stripes": 5_000_000,
            },
        )
        self.index = idx
        self.index_merkle_root = merkle_root
        self.anchors_meta = idx.get("anchors", [])
        # Build entries list
        self.entries = []
        archive_size = os.fstat(self.f.fileno()).st_size
        for ent in idx.get("entries", []):
            e = Entry(
                entry_id=ent["entry_id"],
                kind=ent["kind"],
                path=ent["path"],
            )
            # Path validation: reject NUL and overly long utf-8 (>1024 bytes)
            if "\x00" in e.path:
                raise ValueError("Invalid path contains NUL")
            if len(e.path.encode("utf-8")) > 1024:
                raise ValueError("Path length exceeds 1024 bytes")
            if "mode" in ent:
                e.mode = ent.get("mode", 0)
            if "mtime" in ent and isinstance(ent["mtime"], dict):
                e.mtime_sec = int(ent["mtime"].get("sec", 0))
                e.mtime_nsec = int(ent["mtime"].get("nsec", 0))
            if "atime" in ent and isinstance(ent["atime"], dict):
                e.atime_sec = int(ent["atime"].get("sec", 0))
                e.atime_nsec = int(ent["atime"].get("nsec", 0))
            if e.kind == 0:
                e.size = ent.get("size", 0)
                e.file_codec = ent.get("file_codec", CODEC_NONE)
                e.chunk_size = ent.get("chunk_size", 0)
                e.chunks = []
                for ch in ent.get("chunks", []):
                    # Chunk bounds and size validation
                    ulen = ch["uncompressed_len"]
                    if e.chunk_size and ulen > e.chunk_size:
                        raise ValueError("Chunk uncompressed_len exceeds declared chunk_size")
                    off = ch["offset"]
                    poff = ch.get("payload_offset", 0)
                    plen = ch["payload_len"]
                    if off < 0 or off >= archive_size:
                        raise ChunkBoundsError("Chunk offset out of range")
                    if poff < 0 or poff >= archive_size:
                        raise ChunkBoundsError("Chunk payload_offset out of range")
                    if plen < 0 or poff + plen > archive_size:
                        raise ChunkBoundsError("Chunk payload length out of range")
                    e.chunks.append(
                        ChunkDesc(
                            offset=ch["offset"],
                            payload_offset=ch.get("payload_offset", 0),
                            payload_len=ch["payload_len"],
                            uncompressed_len=ch["uncompressed_len"],
                            chunk_index=ch["chunk_index"],
                            tag16=ch["blake2s_16"],
                        )
                    )
                if "file_blake2s_32" in ent:
                    e.file_hash32 = ent["file_blake2s_32"]
            if e.kind == 2 and "symlink_target" in ent:
                e.symlink_target = ent["symlink_target"]
            self.entries.append(e)

        # Validate Merkle matches what we would compute from index tags
        calc = self._compute_merkle_from_index()
        if calc != merkle_root:
            raise MerkleMismatch("Index Merkle root mismatch")
        self._load_ecc_groups()
        self._load_anchor_records()

    def _compute_merkle_from_index(self) -> bytes:
        # Flatten tags in file order from index entries
        leaves: List[bytes] = []
        for e in self.entries:
            if e.kind != 0:
                continue
            for ch in e.chunks:
                leaves.append(merkle_leaf_from_chunk_tag(ch.tag16))
        if not leaves:
            return b"\x00" * 32
        level = leaves
        while len(level) > 1:
            nxt: List[bytes] = []
            it = iter(level)
            for left in it:
                try:
                    right = next(it)
                except StopIteration:
                    nxt.append(left)
                    break
                nxt.append(merkle_parent(left, right))
            level = nxt
        return level[0]

    def _load_ecc_groups(self):
        """
        Loads and merges ECC group information from the index.

        Archives that have been appended to may have multiple ECC groups. This
        function merges the symbol and stripe information from all groups into
        a single, unified view for the reader. It also performs validation to
        ensure that critical parameters like `symbol_size` are consistent
        across all groups.
        """
        self.symbols = []
        self.stripes = []
        if not self.index:
            return
        groups = self.index.get("ecc_groups", [])
        if not groups:
            return
        # Merge all groups (safe append segments)
        symbol_map = {}
        self.symbols = []
        self.stripes = []
        self.rx_parities = []
        # symbol size must match across groups; take from first group
        if groups:
            self.symbol_size = groups[0].get("symbol_size", 65536)
        # For bounds checking
        fsize = os.fstat(self.f.fileno()).st_size if self.f is not None else 0
        for g in groups:
            if g.get("symbol_size", self.symbol_size) != self.symbol_size:
                raise SymbolSizeMismatchError("Mismatched symbol_size across ECC groups")
            for sym in g.get("symbols", []):
                record_offset = sym.get("record_offset")
                if record_offset is None:
                    raise ValueError("ECC symbol missing record_offset in index")
                info = SymbolInfo(
                    symbol_index=sym["symbol_index"],
                    offset=sym["offset"],
                    record_offset=record_offset,
                    length=sym["length"],
                    tag16=sym["tag16"],
                    stripe_index=sym.get("stripe_index", -1),
                    is_parity=bool(sym.get("is_parity", False)),
                    seed_base=sym.get("seed_base"),
                )
                max_len = self.symbol_size
                if info.is_parity and self.decryptor is not None:
                    max_len += self.decryptor.overhead()
                if info.length < 0 or info.length > max_len:
                    raise SymbolBoundsError("ECC symbol length out of range")
                if info.offset < 0 or info.offset + info.length > fsize:
                    raise SymbolBoundsError("ECC symbol offset/length out of range")
                if info.symbol_index in symbol_map:
                    raise DuplicateSymbolIndexError("Duplicate ECC symbol index across groups")
                symbol_map[info.symbol_index] = info
            for stripe in g.get("stripes", []):
                self.stripes.append(
                    StripeInfo(
                        stripe_index=stripe["stripe_index"],
                        data_symbols=list(stripe.get("data_symbols", [])),
                        parity_symbol=stripe.get("parity_symbol"),
                    )
                )
            rx = g.get("rx")
            if rx:
                g_seed_base = rx.get("seed_base", b"")
                for item in rx.get("parity", []):
                    item_seed_base = item.get("seed_base", g_seed_base)
                    self.rx_parities.append(
                        RXParityInfo(
                            symbol_index=item["symbol_index"],
                            seed_id=item.get("seed_id", 0),
                            offset=item.get("offset", 0),
                            length=item.get("length", self.symbol_size),
                            tag16=item.get("tag16", b""),
                            seed_base=item_seed_base,
                        )
                    )
        if symbol_map:
            max_index = max(symbol_map.keys())
            for i in range(max_index + 1):
                if i not in symbol_map:
                    raise SymbolIndexGapError("ECC symbol index gap detected")
                self.symbols.append(symbol_map[i])

    def _load_anchor_records(self):
        self.anchors_data = []
        if not self.anchors_meta:
            return
        if self.f is None:
            return
        failed = 0
        total = 0
        for meta in self.anchors_meta:
            off = meta.get("offset")
            if off is None:
                continue
            total += 1
            try:
                rtype, rflags, hdr_ext, payload = read_record_at(self.f, off, decryptor=self.decryptor)
            except (AmberError, OSError, ValueError, RuntimeError):
                failed += 1
                continue
            if rtype != RTYPE_ANCHOR:
                failed += 1
                continue
            try:
                anchor = tlv.loads_anchor(payload, max_symbols=1024)
            except ValueError:
                failed += 1
                continue
            anchor["offset"] = off
            self.anchors_data.append(anchor)
        self.anchor_total_count = total
        self.anchor_fail_count = failed

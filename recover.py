from __future__ import annotations

import os
import struct
import sys
from typing import Dict, List, Optional, Tuple
from collections import Counter

from .superblock import read_superblock
from .encryption import EncryptionContext, EncryptionParams
from .records import _REC_HDR_STRUCT, read_exact, parse_chunk_header_ext, read_record_at
from .constants import REC_SYNC
from .constants import (
    RTYPE_ENTRY_BEGIN,
    RTYPE_ENTRY_END,
    RTYPE_CHUNK,
    RTYPE_ANCHOR,
    CODEC_LRP_PARITY,
    CODEC_RX_PARITY,
    INDEX_FRAME_MAGIC,
    INDEX_LOC_MAGIC,
    FLAG_ENCRYPTED,
)
from .hashutil import blake2s_32, blake2s_16, merkle_leaf_from_chunk_tag, merkle_parent
from .crc32c import crc32c
from . import tlv


_IDX_FRAME_HDR = struct.Struct("<8sI Q 32s 32s")
_IDX_LOC_STRUCT = struct.Struct("<8sQQI16sI")


def _compute_merkle_from_entries(entries: List[Dict]) -> bytes:
    leaves: List[bytes] = []
    for e in entries:
        if e.get("kind") != 0:
            continue
        for ch in e.get("chunks", []):
            leaves.append(merkle_leaf_from_chunk_tag(ch.get("blake2s_16", b"")))
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


def rebuild_index(path: str, *, password: Optional[str] = None) -> int:
    """Rebuild a minimal index and anchor by scanning records.

    Returns number of RX parity symbols discovered.
    """
    sb = None
    decryptor: Optional[EncryptionContext] = None
    entries: List[Dict] = []
    entry_map: Dict[int, Dict] = {}
    symbols: List[Dict] = []
    stripes: List[Dict] = []
    rx_parities: List[Dict] = []
    pending_stripe_syms: List[int] = []
    symbol_size = 65536
    rx_seed_base: bytes = b""
    anchors_meta_raw: List[Dict] = []

    with open(path, "rb") as f:
        # Superblock
        sb = read_superblock(f)
        if sb.flags & 1:  # FLAG_ENCRYPTED
            if not password:
                raise ValueError("Archive is encrypted; password required for index rebuild")
            if sb.kdf_id != 1:
                raise ValueError("Unsupported KDF for encrypted archive")
            params = EncryptionParams(
                salt=sb.kdf_salt,
                time_cost=sb.argon_time_cost,
                memory_cost_kib=sb.argon_memory_cost,
                parallelism=sb.argon_parallelism,
            )
            decryptor = EncryptionContext.from_params(password, params)

        # Scan records from after superblock to EOF
        import amber.superblock as _sbmod
        f.seek(_sbmod._SUPERBLOCK_STRUCT.size)
        while True:
            try:
                rec_start = f.tell()
                fixed = read_exact(f, _REC_HDR_STRUCT.size)
            except EOFError:
                break
            sync, rtype, rflags, header_len, payload_len, hdr_crc, _reserved = _REC_HDR_STRUCT.unpack(fixed)
            if sync != REC_SYNC:
                break
            header_ext = read_exact(f, header_len) if header_len else b""
            # Validate header CRC, then read payload raw
            if crc32c(fixed[:-8] + header_ext) != hdr_crc:
                # Stop scanning on corruption
                break
            payload_offset = f.tell()
            try:
                payload = read_exact(f, payload_len)
            except EOFError:
                # Truncated payload; stop scanning gracefully
                break
            header_bytes = fixed + header_ext
            # Optionally decrypt metadata payloads (EntryBegin/Anchor), but leave chunk payloads raw for symbolization
            dec_payload = payload
            if decryptor is not None and rtype in (RTYPE_ENTRY_BEGIN, RTYPE_ANCHOR):
                try:
                    dec_payload = decryptor.decrypt(header_bytes, payload)
                except ValueError as exc:
                    raise RuntimeError("Failed to decrypt metadata record during index rebuild") from exc

            if rtype == RTYPE_ENTRY_BEGIN:
                # Parse minimal fields we care about
                ent: Dict = {"chunks": []}
                for tag, pl in tlv._iter_tlvs(dec_payload):
                    if tag == 1:
                        ent["entry_id"], _ = tlv._varint_decode(pl, 0)
                    elif tag == 2:
                        ent["kind"], _ = tlv._varint_decode(pl, 0)
                    elif tag == 3:
                        ent["path"] = tlv._decode_str(pl)
                    elif tag == 4:
                        ent["mode"], _ = tlv._varint_decode(pl, 0)
                    elif tag == 5:
                        s, pos = tlv._varint_decode(pl, 0)
                        ns, pos = tlv._varint_decode(pl, pos)
                        ent["mtime"] = {"sec": s, "nsec": ns}
                    elif tag == 6:
                        s, pos = tlv._varint_decode(pl, 0)
                        ns, pos = tlv._varint_decode(pl, pos)
                        ent["atime"] = {"sec": s, "nsec": ns}
                    elif tag == 7:
                        ent["size"], _ = tlv._varint_decode(pl, 0)
                    elif tag == 8:
                        ent["file_codec"], _ = tlv._varint_decode(pl, 0)
                    elif tag == 9:
                        ent["chunk_size"], _ = tlv._varint_decode(pl, 0)
                    elif tag == 10:
                        ent["symlink_target"] = tlv._decode_str(pl)
                eid = int(ent.get("entry_id", 0))
                if eid:
                    entries.append(ent)
                    entry_map[eid] = ent
            elif rtype == RTYPE_CHUNK:
                entry_id, chunk_index, ulen, codec_id, _flags, tag16, aux16 = parse_chunk_header_ext(header_ext)
                # Chunk record always has header ext
                # Record chunk info
                if entry_id:
                    em = entry_map.get(entry_id)
                    if em is not None:
                        em.setdefault("kind", 0)
                        em["_raw_chunk_count"] = int(em.get("_raw_chunk_count", 0)) + 1
                        em.setdefault("chunks", []).append(
                            {
                                "offset": rec_start,
                                "payload_offset": payload_offset,
                                "payload_len": payload_len,
                                "uncompressed_len": ulen,
                                "chunk_index": chunk_index,
                                "blake2s_16": tag16,
                            }
                        )
                header_bytes = fixed + header_ext
                is_parity = codec_id in (CODEC_LRP_PARITY, CODEC_RX_PARITY)
                dec_payload = payload
                if decryptor is not None and is_parity:
                    try:
                        dec_payload = decryptor.decrypt(header_bytes, payload)
                    except ValueError as exc:
                        raise RuntimeError("Failed to decrypt parity record during index rebuild") from exc
                if is_parity:
                    sym_index = len(symbols)
                    parity_tag = blake2s_16(dec_payload[: symbol_size])
                    symbols.append(
                        {
                            "symbol_index": sym_index,
                            "offset": payload_offset,
                            "record_offset": rec_start,
                            "length": len(payload),
                            "tag16": parity_tag,
                            "stripe_index": chunk_index if codec_id == CODEC_LRP_PARITY else -1,
                            "is_parity": True,
                            "seed_base": aux16 if codec_id == CODEC_RX_PARITY else None,
                        }
                    )
                    if codec_id == CODEC_LRP_PARITY:
                        stripes.append(
                            {
                                "stripe_index": chunk_index,
                                "data_symbols": pending_stripe_syms[:],
                                "parity_symbol": sym_index,
                            }
                        )
                        pending_stripe_syms.clear()
                    else:
                        rx_parities.append(
                            {
                                "symbol_index": sym_index,
                                "seed_id": chunk_index,
                                "offset": payload_offset,
                                "length": len(payload),
                                "tag16": parity_tag,
                                "seed_base": aux16,
                            }
                        )
                else:
                    pos = 0
                    while pos < len(payload):
                        sym_bytes = payload[pos : pos + symbol_size]
                        sym_index = len(symbols)
                        symbols.append(
                            {
                                "symbol_index": sym_index,
                                "offset": payload_offset + pos,
                                "record_offset": rec_start,
                                "length": len(sym_bytes),
                                "tag16": blake2s_16(sym_bytes),
                                "stripe_index": -1,
                                "is_parity": False,
                                "seed_base": None,
                            }
                        )
                        pending_stripe_syms.append(sym_index)
                        pos += len(sym_bytes)
            elif rtype == RTYPE_ANCHOR:
                try:
                    an = tlv.loads_anchor(dec_payload)
                    declared_symbol_size = int(an.get("symbol_size", symbol_size))
                    seed_base_val = an.get("seed_base", b"")
                    version_val = int(an.get("version", 1))
                    syms = an.get("symbols", []) or []
                    sanitized_syms: List[Dict] = []
                    for s in syms:
                        if not isinstance(s, dict):
                            continue
                        try:
                            sym_index = int(s.get("symbol_index", -1))
                            offset_val = int(s.get("offset", 0))
                            length_val = int(s.get("length", 0))
                        except (TypeError, ValueError):
                            continue
                        tag_val = s.get("tag16", b"")
                        if isinstance(tag_val, bytearray):
                            tag_val = bytes(tag_val)
                        entry = {
                            "symbol_index": sym_index,
                            "offset": offset_val,
                            "length": length_val,
                            "tag16": tag_val,
                            "is_parity": bool(s.get("is_parity", False)),
                        }
                        if "record_offset" in s:
                            try:
                                entry["record_offset"] = int(s.get("record_offset", 0))
                            except (TypeError, ValueError):
                                entry["record_offset"] = None
                        sanitized_syms.append(entry)
                    anchors_meta_raw.append({
                        "offset": rec_start,
                        "symbols": sanitized_syms,
                        "seed_base": seed_base_val,
                        "symbol_size": declared_symbol_size,
                        "version": version_val,
                    })
                except (TypeError, ValueError) as exc:
                    print("Warning: skipping malformed anchor payload during index rebuild:", str(exc), file=sys.stderr)
            # Advance offset for next loop
            offset = f.tell()

    # Validate anchors against recovered symbol metadata
    symbol_by_offset: Dict[int, Dict] = {int(s["offset"]): s for s in symbols}
    validated_anchors: List[Dict] = []
    for entry in anchors_meta_raw:
        syms = entry.get("symbols", [])
        version_val = int(entry.get("version", 0) or 0)
        declared_size = int(entry.get("symbol_size", symbol_size))
        if version_val != 1:
            continue
        if declared_size != symbol_size:
            continue
        valid = True
        for sample in syms:
            if not isinstance(sample, dict):
                valid = False
                break
            try:
                sample_offset = int(sample.get("offset", -1))
            except (TypeError, ValueError):
                valid = False
                break
            base = symbol_by_offset.get(sample_offset)
            if base is None:
                valid = False
                break
            if int(base.get("length", -1)) != int(sample.get("length", -1)):
                valid = False
                break
            if bool(base.get("is_parity", False)) != bool(sample.get("is_parity", False)):
                valid = False
                break
            sample_ro = sample.get("record_offset")
            base_ro = base.get("record_offset")
            if sample_ro is not None and base_ro is not None and int(sample_ro) != int(base_ro):
                valid = False
                break
            sample_sb = sample.get("seed_base")
            base_sb = base.get("seed_base")
            if sample_sb is not None and base_sb is not None and bytes(sample_sb) != bytes(base_sb):
                valid = False
                break
            if decryptor is None:
                base_tag = base.get("tag16", b"")
                sample_tag = sample.get("tag16", b"")
                if isinstance(base_tag, bytearray):
                    base_tag = bytes(base_tag)
                if isinstance(sample_tag, bytearray):
                    sample_tag = bytes(sample_tag)
                if not isinstance(sample_tag, (bytes, bytearray)) or len(sample_tag) != 16:
                    valid = False
                    break
                if base_tag and bytes(sample_tag) != bytes(base_tag):
                    valid = False
                    break
        if not valid:
            continue
        count = len(syms)
        first_symbol = syms[0]["symbol_index"] if count else 0
        last_symbol = syms[-1]["symbol_index"] if count else 0
        validated_anchors.append(
            {
                "offset": entry.get("offset", 0),
                "symbol_count": count,
                "first_symbol": first_symbol,
                "last_symbol": last_symbol,
                "seed_base": entry.get("seed_base", b""),
            }
        )

    seed_candidates = [e["seed_base"] for e in validated_anchors if isinstance(e.get("seed_base"), (bytes, bytearray))]
    canonical_seed_base = b""
    if seed_candidates:
        counts = Counter(seed_candidates)
        # Prefer non-empty seed if available
        if any(sb for sb in counts.keys() if sb):
            non_empty = {sb: cnt for sb, cnt in counts.items() if sb}
            canonical_seed_base = max(non_empty.items(), key=lambda kv: kv[1])[0]
        else:
            canonical_seed_base = counts.most_common(1)[0][0]
        canonical_seed_base = bytes(canonical_seed_base)

    anchors: List[Dict] = []
    for entry in validated_anchors:
        seed_bytes = entry.get("seed_base")
        if canonical_seed_base and seed_bytes and bytes(seed_bytes) != canonical_seed_base:
            continue
        anchors.append({
            "offset": entry["offset"],
            "symbol_count": entry["symbol_count"],
            "first_symbol": entry["first_symbol"],
            "last_symbol": entry["last_symbol"],
        })
    if canonical_seed_base:
        rx_seed_base = bytes(canonical_seed_base)

    # Validate and filter chunk offsets by re-reading record headers
    with open(path, "rb") as vf:
        for ent in entries:
            if ent.get("kind") != 0:
                ent.pop("_raw_chunk_count", None)
                continue
            good: List[Dict] = []
            for ch in ent.get("chunks", []):
                try:
                    # For validation we only need the header; avoid decrypting payloads
                    rtype, _rf, hdr_ext, _payload = read_record_at(vf, ch["offset"], decryptor=None)
                    if rtype != RTYPE_CHUNK:
                        continue
                    eid, _idx, _ulen, _codec, _flags, _tag, _aux = parse_chunk_header_ext(hdr_ext)
                    if int(eid) != int(ent.get("entry_id", 0)):
                        continue
                    good.append(ch)
                except (EOFError, OSError, ValueError):
                    continue
            ent["chunks"] = sorted(good, key=lambda c: c.get("chunk_index", 0))
    # Sanity check: abort if we'd emit metadata for a file that clearly has data but no chunks
    problematic: List[str] = []
    for ent in entries:
        if ent.get("kind") != 0:
            ent.pop("_raw_chunk_count", None)
            continue
        raw_count = int(ent.get("_raw_chunk_count", 0) or 0)
        ent.pop("_raw_chunk_count", None)
        chunk_count = len(ent.get("chunks", []))
        size = int(ent.get("size", 0) or 0)
        if (raw_count == 0 and size > 0) or (raw_count > 0 and chunk_count == 0):
            name = ent.get("path") or f"entry#{ent.get('entry_id', 0)}"
            problematic.append(str(name))
    if problematic:
        names = ", ".join(problematic)
        raise RuntimeError(f"Index rebuild aborted: missing chunk metadata for {names}")

    # Build ECC group and index map
    rx_info = None
    if rx_seed_base and rx_parities:
        rx_info = {
            "seed_base": rx_seed_base,
            "epsilon_ppm": int(len(rx_parities) * 1_000_000 / max(1, len([s for s in symbols if not s.get("is_parity")]))),
            "parity": rx_parities,
        }
    idx_map = {
        "version": {"major": 1, "minor": 0},
        "archive_uuid": sb.uuid if sb else b"\x00" * 16,
        "writer_info": "amber-recover",
        "default_chunk_size": sb.default_chunk_size if sb else 0,
        "default_codec": sb.default_codec if sb else 0,
        "entries": entries,
        "ecc_groups": [
            {
                "group_id": 1,
                "symbol_size": symbol_size,
                "lrp": {"k": 0, "p": 0},
                **({"rx": rx_info} if rx_info else {}),
                "symbols": symbols,
                "stripes": stripes,
            }
        ],
        "anchors": anchors,
    }
    merkle_root = _compute_merkle_from_entries(entries)
    idx_payload = tlv.dumps_index(idx_map)
    # Write index frames and locators
    with open(path, "rb+") as outf:
        outf.seek(0, os.SEEK_END)
        frame_flags = 0
        import zlib

        compressed = zlib.compress(idx_payload, level=6)
        if len(compressed) < len(idx_payload):
            frame_flags |= 1
        else:
            compressed = idx_payload
        frame_hash = blake2s_32(idx_payload)
        is_encrypted = bool(sb and (sb.flags & FLAG_ENCRYPTED))
        if is_encrypted and decryptor is not None:
            frame_flags |= 2
        frame_plain = _IDX_FRAME_HDR.pack(INDEX_FRAME_MAGIC, frame_flags, len(idx_payload), frame_hash, merkle_root)
        frame_plain += compressed
        frame_crc = crc32c(frame_plain)
        frame_plain += struct.pack("<I", frame_crc)
        # two frames
        locs = []
        for seq in (0, 1):
            start = outf.tell()
            if is_encrypted and decryptor is not None:
                frame = decryptor.encrypt(b"IDXFRAME", frame_plain, nonce_material=struct.pack("<Q", start))
            else:
                frame = frame_plain
            outf.write(frame)
            locs.append((seq, start, len(frame)))
        for seq, start, flen in locs:
            loc_crc = crc32c(INDEX_LOC_MAGIC + struct.pack("<QQI16s", flen, start, seq, sb.uuid if sb else b"\x00" * 16))
            loc = _IDX_LOC_STRUCT.pack(INDEX_LOC_MAGIC, flen, start, seq, sb.uuid if sb else b"\x00" * 16, loc_crc)
            outf.write(loc)
        outf.flush()
        os.fsync(outf.fileno())
    return len(rx_parities)

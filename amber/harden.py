from __future__ import annotations

import copy
import os
import struct
from typing import Dict, List, Optional

from . import tlv

from .reader import ArchiveReader, SymbolInfo, RXParityInfo
from .records import write_record, build_chunk_header_ext
from .constants import (
    CODEC_RX_PARITY,
    RFLAG_CHUNK_TAG_PRESENT,
    RFLAG_PARITY_RECORD,
    RTYPE_CHUNK,
    RTYPE_ANCHOR,
    INDEX_FRAME_MAGIC,
    INDEX_LOC_MAGIC,
    FLAG_ENCRYPTED,
)
from .hashutil import blake2s_16, blake2s_32, merkle_leaf_from_chunk_tag, merkle_parent
from .gf256 import gf_mul_bytes, gf_add_bytes
from .crc32c import crc32c
from .encryption import EncryptionContext
from .trailer import build_anchor_payload, write_anchor_record


_IDX_FRAME_HDR = struct.Struct("<8sI Q 32s 32s")
_IDX_LOC_STRUCT = struct.Struct("<8sQQI16sI")


def append_rx_parity(path: str, extra_ppm: int = 10000, password: Optional[str] = None) -> int:
    """Append additional RX parity symbols and rewrite anchors/index.

    Returns the number of new parity symbols written.
    """

    with ArchiveReader(path, password=password) as reader:
        def _gid(group):
            try:
                return int(group.get("group_id", 0) or 0)
            except (TypeError, ValueError):
                return 0

        groups = reader.index.get("ecc_groups")
        if not groups or not isinstance(groups, list):
            raise RuntimeError("Missing ECC groups in index")
        target_group = max(groups, key=_gid)
        group_symbols_meta = target_group.get("symbols", []) or []
        group_data_indices = sorted(
            int(item.get("symbol_index", -1))
            for item in group_symbols_meta
            if isinstance(item, dict) and not bool(item.get("is_parity", False)) and int(item.get("symbol_index", -1)) >= 0
        )
        if not group_data_indices:
            return 0
        data_indices = group_data_indices
        n = len(data_indices)
        base = n * extra_ppm // 1_000_000
        target = max(2 if n >= 2 else 1, base)
        start_seed = len([p for p in target_group.get("rx", {}).get("parity", []) or []])
        symbol_size = reader.symbol_size
        if not reader.index:
            raise RuntimeError("Missing index in archive")
        rx_info = target_group.get("rx")
        if not isinstance(rx_info, dict) or "seed_base" not in rx_info:
            raise RuntimeError("Missing RX seed_base in index")
        seed_base = rx_info["seed_base"]
        index_map = copy.deepcopy(reader.index)
        merkle_root = reader.index_merkle_root or _compute_merkle_root_from_index(index_map)
        symbol_infos = [SymbolInfo(**vars(sym)) for sym in reader.symbols]
        target_rx_parities = list(rx_info.get("parity", [])) if isinstance(rx_info.get("parity"), list) else []
        anchors_meta = list(reader.anchors_meta)
        encryptor = reader.decryptor
        archive_uuid = reader.superblock.uuid if reader.superblock else b"\x00" * 16
        is_encrypted = bool(reader.superblock and (reader.superblock.flags & FLAG_ENCRYPTED))

        symbol_bytes: Dict[int, bytes] = {}
        fh = reader.f
        for idx in data_indices:
            sym = reader.symbols[idx]
            fh.seek(sym.offset)
            data = fh.read(sym.length)
            buf = bytearray(symbol_size)
            buf[: sym.length] = data
            symbol_bytes[idx] = bytes(buf)
        truncate_offset = reader.index_region_start
        if anchors_meta:
            last_anchor_off = max(int(meta.get("offset", reader.index_region_start)) for meta in anchors_meta)
            truncate_offset = max(last_anchor_off, reader.index_region_start)

    if target <= 0:
        return 0

    new_parities: List[RXParityInfo] = []
    new_anchor_meta: Dict[str, int] | None = None
    with open(path, "rb+") as outf:
        outf.truncate(truncate_offset)
        outf.seek(truncate_offset)

        for i in range(target):
            seed_id = start_seed + i
            from .rx import sample_rx_combination
            combo = sample_rx_combination(seed_base, seed_id, data_indices)
            parity_bytes = _compute_rx_payload(symbol_bytes, combo, symbol_size)
            tag16 = blake2s_16(parity_bytes)
            hdr_ext = build_chunk_header_ext(0, seed_id, symbol_size, CODEC_RX_PARITY, tag16, aux16=seed_base)
            rflags = RFLAG_CHUNK_TAG_PRESENT | RFLAG_PARITY_RECORD
            parity_encryptor = encryptor if is_encrypted and encryptor is not None else None
            record_offset, payload_offset, final_payload = write_record(
                outf, RTYPE_CHUNK, rflags, hdr_ext, parity_bytes, encryptor=parity_encryptor
            )
            symbol_index = len(symbol_infos)
            symbol_infos.append(
                SymbolInfo(
                    symbol_index=symbol_index,
                    offset=payload_offset,
                    record_offset=record_offset,
                    length=len(final_payload),
                    tag16=tag16,
                    stripe_index=-1,
                    is_parity=True,
                    seed_base=seed_base,
                )
            )
            rx_parity = {
                "symbol_index": symbol_index,
                "seed_id": seed_id,
                "offset": payload_offset,
                "length": len(final_payload),
                "tag16": tag16,
                "seed_base": seed_base,
            }
            target_rx_parities.append(rx_parity)
            new_parities.append(rx_parity)
            symbol_bytes[symbol_index] = final_payload
            new_symbol_meta = {
                "symbol_index": symbol_index,
                "offset": payload_offset,
                "record_offset": record_offset,
                "length": len(final_payload),
                "tag16": tag16,
                "stripe_index": -1,
                "is_parity": True,
                "seed_base": seed_base,
            }
            group_symbols_meta.append(new_symbol_meta)

        # Anchor record via shared helpers
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
            for info in symbol_infos
        ]
        anchor_payload = build_anchor_payload(symbol_dicts, symbol_size, merkle_root, seed_base)
        anchor_offset = write_anchor_record(outf, encryptor, anchor_payload)
        new_anchor_meta = {
            "offset": anchor_offset,
            "symbol_count": min(64, len(symbol_infos)),
            "first_symbol": symbol_infos[-min(64, len(symbol_infos))].symbol_index if symbol_infos else 0,
            "last_symbol": symbol_infos[-1].symbol_index if symbol_infos else 0,
        }

        # Build updated index map
        updated_index = copy.deepcopy(index_map)
        if not updated_index:
            updated_index = {}
        groups = updated_index.get("ecc_groups", [])
        if not groups:
            groups = [{}]
            updated_index["ecc_groups"] = groups
        gid = _gid(target_group)
        group = None
        for candidate in groups:
            if _gid(candidate) == gid:
                group = candidate
                break
        if group is None:
            group = groups[0]
        group["symbol_size"] = symbol_size
        group["symbols"] = group_symbols_meta
        grf = group.get("rx", {})
        grf["seed_base"] = seed_base
        total_parity = len(target_rx_parities)
        data_count = len(data_indices)
        epsilon_ppm = 0
        if data_count:
            epsilon_ppm = int(total_parity * 1_000_000 / data_count)
        grf["epsilon_ppm"] = epsilon_ppm
        grf["parity"] = target_rx_parities
        group["rx"] = grf
        # Preserve prior good anchors before truncate point and add new tail anchor
        prior_anchors = []
        for am in (anchors_meta or []):
            try:
                off = int(am.get("offset", -1))
            except (TypeError, ValueError):
                continue
            if 0 <= off < truncate_offset:
                prior_anchors.append(am)
        updated_index["anchors"] = (prior_anchors + [new_anchor_meta]) if new_anchor_meta else prior_anchors

        idx_payload = tlv.dumps_index(updated_index)

        import zlib

        frame_flags = 0
        compressed = zlib.compress(idx_payload, level=6)
        if len(compressed) < len(idx_payload):
            frame_flags |= 1
        else:
            compressed = idx_payload

        index_hash = blake2s_32(idx_payload)
        if is_encrypted and encryptor is not None:
            frame_flags |= 2
        frame_plain = _IDX_FRAME_HDR.pack(INDEX_FRAME_MAGIC, frame_flags, len(idx_payload), index_hash, merkle_root)
        frame_plain += compressed
        frame_crc = crc32c(frame_plain)
        frame_plain += struct.pack("<I", frame_crc)

        # Two-phase trailer writes: frames then locators
        frame_locs = []
        for seq in (0, 1):
            frame_start = outf.tell()
            frame = (
                encryptor.encrypt(b"IDXFRAME", frame_plain, nonce_material=struct.pack("<Q", frame_start))
                if (is_encrypted and encryptor is not None)
                else frame_plain
            )
            outf.write(frame)
            outf.flush()
            os.fsync(outf.fileno())
            frame_locs.append((seq, frame_start, len(frame)))
        for seq, frame_start, flen in frame_locs:
            loc_crc = crc32c(INDEX_LOC_MAGIC + struct.pack("<QQI16s", flen, frame_start, seq, archive_uuid))
            loc = _IDX_LOC_STRUCT.pack(INDEX_LOC_MAGIC, flen, frame_start, seq, archive_uuid, loc_crc)
            outf.write(loc)
        outf.flush()
        os.fsync(outf.fileno())

    return len(new_parities)


# RX sampling is centralized in amber.rx.sample_rx_combination


def _compute_rx_payload(symbol_bytes: Dict[int, bytes], combo: List[tuple[int, int]], symbol_size: int) -> bytes:
    parity = bytearray(symbol_size)
    for sym_index, coeff in combo:
        data = symbol_bytes.get(sym_index)
        if data is None:
            data = bytes(symbol_size)
        scaled = gf_mul_bytes(data, coeff)
        gf_add_bytes(parity, scaled)
    return bytes(parity)


# Local _write_anchor removed; using trailer helpers instead


def _compute_merkle_root_from_index(index_map: Dict) -> bytes:
    leaves: List[bytes] = []
    if not index_map:
        return b"\x00" * 32
    for ent in index_map.get("entries", []):
        if ent.get("kind") != 0:
            continue
        for ch in ent.get("chunks", []):
            leaves.append(merkle_leaf_from_chunk_tag(ch.get("blake2s_16", b"")))
    if not leaves:
        return b"\x00" * 32
    while len(leaves) > 1:
        nxt: List[bytes] = []
        it = iter(leaves)
        for left in it:
            try:
                right = next(it)
            except StopIteration:
                nxt.append(left)
                break
            nxt.append(merkle_parent(left, right))
        leaves = nxt
    return leaves[0]

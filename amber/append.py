from __future__ import annotations

import copy
import os
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .reader import ArchiveReader
from .records import write_record, build_chunk_header_ext
from .constants import (
    RTYPE_ENTRY_BEGIN,
    RTYPE_ENTRY_END,
    RTYPE_CHUNK,
    RTYPE_ANCHOR,
    CODEC_RX_PARITY,
)
from .hashutil import blake2s_16, blake2s_32
from .harden import _compute_merkle_root_from_index
from .encryption import EncryptionContext
from .gf256 import gf_mul_bytes, gf_add_bytes
from .tlv import dumps_index
from .entryutil import build_entry_begin_payload
from .pathutil import norm_path
from .chunkemit import ChunkEmitContext, emit_file_chunks


_IDX_FRAME_HDR = struct.Struct("<8sI Q 32s 32s")
_IDX_LOC_STRUCT = struct.Struct("<8sQQI16sI")
INDEX_FRAME_MAGIC = b"AMBRIDX\x00"
INDEX_LOC_MAGIC = b"AMBRLOC\x00"


class _Sym:
    """Captured symbol metadata used to rebuild ECC group structures."""
    def __init__(
        self,
        index: int,
        offset: int,
        record_offset: int,
        length: int,
        tag16: bytes,
        is_parity: bool,
        stripe_index: int = -1,
        seed_base: Optional[bytes] = None,
    ):
        self.index = index
        self.offset = offset
        self.record_offset = record_offset
        self.length = length
        self.tag16 = tag16
        self.is_parity = is_parity
        self.stripe_index = stripe_index
        self.seed_base = seed_base


def _entry_begin_payload(entry_id: int, kind: int, path: str, *, mode: Optional[int] = None,
                         mtime_sec: Optional[int] = None, mtime_nsec: Optional[int] = None,
                         atime_sec: Optional[int] = None, atime_nsec: Optional[int] = None,
                         size: Optional[int] = None, file_codec: Optional[int] = None,
                         chunk_size: Optional[int] = None, symlink_target: Optional[str] = None) -> bytes:
    return build_entry_begin_payload(
        entry_id=entry_id,
        kind=kind,
        path=path,
        mode=mode,
        mtime_sec=mtime_sec,
        mtime_nsec=mtime_nsec,
        atime_sec=atime_sec,
        atime_nsec=atime_nsec,
        size=size,
        file_codec=file_codec,
        chunk_size=chunk_size,
        symlink_target=symlink_target,
    )


def _scan_inputs(paths: List[str]) -> Tuple[List[Tuple[str, Dict[str, Optional[int]]]], List[Tuple[str, str]], List[Tuple[str, str, int]]]:
    """Return separate manifests for directories, symlinks, and files to append.

    Each result entry contains the archive path plus the metadata required to
    reproduce it inside the archive (coarse timestamps, mode bits, file sizes).
    """
    def _split(st):
        try:
            ns = st.st_mtime_ns
            m_sec, m_nsec = int(ns // 1_000_000_000), int(ns % 1_000_000_000)
        except (AttributeError, ValueError):
            m_sec, m_nsec = int(st.st_mtime), 0
        try:
            ns = st.st_atime_ns
            a_sec, a_nsec = int(ns // 1_000_000_000), int(ns % 1_000_000_000)
        except (AttributeError, ValueError):
            a_sec, a_nsec = int(st.st_atime), 0
        return m_sec, m_nsec, a_sec, a_nsec

    dirs: List[Tuple[str, Dict[str, Optional[int]]]] = []
    symlinks: List[Tuple[str, str]] = []
    files: List[Tuple[str, str, int]] = []
    for p in [Path(x) for x in paths]:
        if p.is_symlink():
            symlinks.append((norm_path(p.name), os.readlink(str(p))))
        elif p.is_dir():
            base = norm_path(p.name)
            try:
                st = os.stat(str(p))
                mode = st.st_mode & 0o7777
                m_sec, m_nsec, a_sec, a_nsec = _split(st)
            except OSError:
                mode = None
                m_sec = m_nsec = a_sec = a_nsec = None
            dirs.append((base, {"mode": mode, "mtime_sec": m_sec, "mtime_nsec": m_nsec, "atime_sec": a_sec, "atime_nsec": a_nsec}))
            for root, dirnames, filenames in os.walk(str(p)):
                for d in dirnames:
                    sub = os.path.join(root, d)
                    rel = os.path.relpath(sub, start=str(p))
                    arc = norm_path(os.path.join(base, rel))
                    try:
                        st = os.stat(sub)
                        dmode = st.st_mode & 0o7777
                        m_sec, m_nsec, a_sec, a_nsec = _split(st)
                    except OSError:
                        dmode = None
                        m_sec = m_nsec = a_sec = a_nsec = None
                    dirs.append((arc, {"mode": dmode, "mtime_sec": m_sec, "mtime_nsec": m_nsec, "atime_sec": a_sec, "atime_nsec": a_nsec}))
                for f in filenames:
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, start=str(p))
                    arc = norm_path(os.path.join(base, rel))
                    try:
                        size = os.path.getsize(full)
                    except OSError:
                        size = 0
                    files.append((arc, full, size))
        else:
            try:
                size = os.path.getsize(str(p))
            except OSError:
                size = 0
            files.append((norm_path(p.name), str(p), size))
    return dirs, symlinks, files


def append_to_archive(archive_path: str, inputs: List[str], *, password: Optional[str] = None, ecc_profile: Optional[str] = None) -> None:
    """Append new paths to an existing archive and refresh its parity and index."""
    with ArchiveReader(archive_path, password=password) as r:
        truncate_offset = r.index_region_start
        if r.anchors_meta:
            last_anchor_off = max(int(meta.get("offset", r.index_region_start)) for meta in r.anchors_meta)
            truncate_offset = max(last_anchor_off, r.index_region_start)
        sb = r.superblock
        if sb is None:
            raise ValueError("Missing superblock")
        default_chunk_size = sb.default_chunk_size
        default_codec = sb.default_codec
        encryptor: Optional[EncryptionContext] = r.decryptor
        symbol_size = r.symbol_size

        lrp_enabled = True
        lrp_k = 16
        profile = (ecc_profile or "balanced").lower()
        if profile == "lean":
            lrp_enabled = False
            lrp_k = 16
            rx_epsilon_ppm = 20000
        elif profile == "archival":
            lrp_enabled = True
            lrp_k = 12
            rx_epsilon_ppm = 40000
        else:
            rx_epsilon_ppm = 20000
        next_symbol_index = 0
        if r.symbols:
            next_symbol_index = max(s.symbol_index for s in r.symbols) + 1
        next_entry_id = 1
        if r.index and r.index.get("entries"):
            next_entry_id = max(int(e.get("entry_id", 0)) for e in r.index.get("entries", [])) + 1

        dirs, symlinks, files = _scan_inputs(inputs)
        index_map = copy.deepcopy(r.index) if r.index else {}
        index_entries = index_map.get("entries", [])
        symbols: List[_Sym] = []
        stripes: List[Dict] = []
        pending_data_syms: List[int] = []
        sym_by_index: Dict[int, _Sym] = {}
        next_stripe_index = 0
        symbol_bytes: Dict[int, bytes] = {}

        with open(archive_path, "rb+") as fh:
            fh.truncate(truncate_offset)
            fh.seek(truncate_offset)
            seen_dirs = set()
            for arc, meta in dirs:
                if arc in seen_dirs:
                    continue
                seen_dirs.add(arc)
                eid = next_entry_id; next_entry_id += 1
                payload = _entry_begin_payload(
                    eid, 1, arc,
                    mode=meta.get("mode"),
                    mtime_sec=meta.get("mtime_sec"), mtime_nsec=meta.get("mtime_nsec"),
                    atime_sec=meta.get("atime_sec"), atime_nsec=meta.get("atime_nsec"),
                )
                write_record(fh, RTYPE_ENTRY_BEGIN, 0, b"", payload, encryptor=encryptor)
                hdr_ext = struct.pack("<QI", eid, 0)
                write_record(fh, RTYPE_ENTRY_END, 0, hdr_ext, b"", encryptor=encryptor)
                entry_meta = {"entry_id": eid, "kind": 1, "path": arc, "mode": meta.get("mode")}
                if meta.get("mtime_sec") is not None:
                    entry_meta["mtime"] = {"sec": meta.get("mtime_sec"), "nsec": meta.get("mtime_nsec", 0)}
                if meta.get("atime_sec") is not None:
                    entry_meta["atime"] = {"sec": meta.get("atime_sec"), "nsec": meta.get("atime_nsec", 0)}
                index_entries.append(entry_meta)

            for arc, target in symlinks:
                eid = next_entry_id; next_entry_id += 1
                payload = _entry_begin_payload(eid, 2, arc, symlink_target=target)
                write_record(fh, RTYPE_ENTRY_BEGIN, 0, b"", payload, encryptor=encryptor)
                hdr_ext = struct.pack("<QI", eid, 0)
                write_record(fh, RTYPE_ENTRY_END, 0, hdr_ext, b"", encryptor=encryptor)
                index_entries.append({"entry_id": eid, "kind": 2, "path": arc, "symlink_target": target})

            import hashlib
            # Prepare a shared chunk emission context across all files so LRP can span file boundaries
            def _symbol_append(sym_index: int, record_offset: int, payload_offset: int, length: int, tag16: bytes, is_parity: bool, stripe_index: int, data_bytes: bytes):
                nonlocal next_stripe_index
                s = _Sym(sym_index, payload_offset, record_offset, length, tag16, is_parity, stripe_index=(stripe_index if is_parity else -1), seed_base=None)
                symbols.append(s)
                sym_by_index[sym_index] = s
                symbol_bytes[sym_index] = data_bytes
                if not is_parity:
                    pending_data_syms.append(sym_index)
                else:
                    # Close stripe over pending data symbols
                    for di in pending_data_syms:
                        if di in sym_by_index:
                            sym_by_index[di].stripe_index = stripe_index
                    stripes.append({"stripe_index": stripe_index, "data_symbols": pending_data_syms.copy(), "parity_symbol": sym_index})
                    pending_data_syms.clear()
                next_stripe_index = max(next_stripe_index, stripe_index + 1 if is_parity else next_stripe_index)

            ctx = ChunkEmitContext(
                fh=fh,
                encryptor=encryptor,
                symbol_size=symbol_size,
                lrp_enabled=lrp_enabled,
                lrp_k=lrp_k,
                next_symbol_index=next_symbol_index,
                next_stripe_index=next_stripe_index,
                symbol_append=_symbol_append,
                on_data_symbol=None,
            )

            for arc, full, _size in files:
                eid = next_entry_id; next_entry_id += 1
                codec_id = default_codec
                chunk_size = default_chunk_size
                st = os.stat(full, follow_symlinks=True)
                size = os.path.getsize(full)
                # pull times
                try:
                    ns = st.st_mtime_ns
                    mtime_sec, mtime_nsec = int(ns // 1_000_000_000), int(ns % 1_000_000_000)
                except (AttributeError, ValueError):
                    mtime_sec, mtime_nsec = int(st.st_mtime), 0
                try:
                    ns = st.st_atime_ns
                    atime_sec, atime_nsec = int(ns // 1_000_000_000), int(ns % 1_000_000_000)
                except (AttributeError, ValueError):
                    atime_sec, atime_nsec = int(st.st_atime), 0
                payload = _entry_begin_payload(
                    eid, 0, arc,
                    mode=(st.st_mode & 0o7777),
                    mtime_sec=mtime_sec, mtime_nsec=mtime_nsec,
                    atime_sec=atime_sec, atime_nsec=atime_nsec,
                    size=size, file_codec=codec_id, chunk_size=chunk_size,
                )
                write_record(fh, RTYPE_ENTRY_BEGIN, 0, b"", payload, encryptor=encryptor)
                chunks, file_hash32 = emit_file_chunks(
                    ctx,
                    entry_id=eid,
                    fs_path=full,
                    codec_id=codec_id,
                    chunk_size=chunk_size,
                )
                # Keep symbol index continuity across files
                next_symbol_index = ctx.next_symbol_index
                next_stripe_index = ctx.next_stripe_index
                hdr_ext = struct.pack("<QI", eid, len(chunks))
                write_record(fh, RTYPE_ENTRY_END, 0, hdr_ext, b"", encryptor=encryptor)
                rec = {
                    "entry_id": eid, "kind": 0, "path": arc, "size": size,
                    "mode": (st.st_mode & 0o7777),
                    "file_codec": codec_id, "chunk_size": chunk_size,
                    "chunks": chunks, "file_blake2s_32": file_hash32,
                }
                if mtime_sec is not None:
                    rec["mtime"] = {"sec": mtime_sec, "nsec": mtime_nsec or 0}
                if atime_sec is not None:
                    rec["atime"] = {"sec": atime_sec, "nsec": atime_nsec or 0}
                index_entries.append(rec)

            # Finalize LRP (flush tail stripe if any)
            ctx.finalize()
            next_symbol_index = ctx.next_symbol_index
            next_stripe_index = ctx.next_stripe_index

            data_indices = sorted([s.index for s in symbols if not s.is_parity])
            target = max(2 if len(data_indices) >= 2 else 1, int(len(data_indices) * rx_epsilon_ppm // 1_000_000)) if data_indices else 0
            rx_seed_base = os.urandom(16)
            rx_parities = []
            from .rx import sample_rx_combination
            for i in range(target):
                seed_id = i
                combo = sample_rx_combination(rx_seed_base, seed_id, data_indices)
                parity = bytearray(symbol_size)
                for sidx, coeff in combo:
                    data = symbol_bytes.get(sidx, bytes(symbol_size))
                    gf_add_bytes(parity, gf_mul_bytes(data, coeff))
                pbytes = bytes(parity)
                ptag = blake2s_16(pbytes)
                phdr = build_chunk_header_ext(0, seed_id, symbol_size, CODEC_RX_PARITY, ptag, aux16=rx_seed_base)
                poff, ppayload_off, pfinal = write_record(fh, RTYPE_CHUNK, 0x02 | 0x04, phdr, pbytes, encryptor=encryptor)
                psym = _Sym(next_symbol_index, ppayload_off, poff, len(pfinal), ptag, is_parity=True, seed_base=rx_seed_base)
                symbols.append(psym)
                symbol_bytes[psym.index] = pfinal
                rx_parities.append({
                    "symbol_index": psym.index,
                    "seed_id": seed_id,
                    "offset": ppayload_off,
                    "length": len(pfinal),
                    "tag16": ptag,
                    "seed_base": rx_seed_base,
                })
                next_symbol_index += 1

            merkle_root = _compute_merkle_root_from_index({"entries": index_entries})
            from .trailer import build_anchor_payload, write_anchor_record, write_index_trailer
            symbol_dicts = [
                {
                    "symbol_index": s.index,
                    "offset": s.offset,
                    "record_offset": s.record_offset,
                    "length": s.length,
                    "tag16": s.tag16,
                    "is_parity": s.is_parity,
                    **({"seed_base": s.seed_base} if s.seed_base else {}),
                }
                for s in symbols
            ]
            anchor_payload = build_anchor_payload(symbol_dicts, symbol_size, merkle_root, rx_seed_base)
            anchor_off = write_anchor_record(fh, encryptor, anchor_payload)
            new_anchor_meta = {
                "offset": anchor_off,
                "symbol_count": min(64, len(symbols)),
                "first_symbol": symbols[-min(64, len(symbols))].index if symbols else 0,
                "last_symbol": symbols[-1].index if symbols else 0,
            }

            groups = index_map.get("ecc_groups", []) or []
            gid = 1
            if groups:
                gid = max(int(g.get("group_id", 0) or 0) for g in groups) + 1
            new_group = {
                "group_id": gid,
                "symbol_size": symbol_size,
                "lrp": ({"k": lrp_k, "p": 1} if lrp_enabled else {"k": 0, "p": 0}),
                "rx": {
                    "seed_base": rx_seed_base,
                    "epsilon_ppm": (int(len(rx_parities) * 1_000_000 / max(1, len([s for s in symbols if not s.is_parity])))),
                    "parity": rx_parities,
                },
                "symbols": [
                    {
                        "symbol_index": s.index,
                        "offset": s.offset,
                        "record_offset": s.record_offset,
                        "length": s.length,
                        "tag16": s.tag16,
                        "stripe_index": s.stripe_index,
                        "is_parity": s.is_parity,
                        **({"seed_base": s.seed_base} if s.seed_base else {}),
                    }
                    for s in symbols
                ],
                "stripes": stripes,
            }
            groups.append(new_group)
            index_map["ecc_groups"] = groups
            index_map["entries"] = index_entries
            prior_anchors = []
            for am in (r.anchors_meta or []):
                if not isinstance(am, dict):
                    continue
                try:
                    off = int(am.get("offset", -1))
                except (TypeError, ValueError):
                    continue
                if 0 <= off < truncate_offset:
                    prior_anchors.append(am)
            index_map["anchors"] = prior_anchors + [new_anchor_meta]

            idx_payload = dumps_index(index_map)
            write_index_trailer(fh, encryptor, sb.uuid, idx_payload, merkle_root)

from __future__ import annotations

import hashlib
from typing import Callable, Dict, List, Optional, Tuple

from .codec import Codec
from .constants import CODEC_LRP_PARITY, RTYPE_CHUNK, RFLAG_CHUNK_TAG_PRESENT, RFLAG_PARITY_RECORD
from .hashutil import blake2s_16
from .records import build_chunk_header_ext, write_record


class ChunkEmitContext:
    def __init__(
        self,
        *,
        fh,
        encryptor,
        symbol_size: int,
        lrp_enabled: bool,
        lrp_k: int,
        next_symbol_index: int,
        next_stripe_index: int,
        # symbol_append arguments:
        # (symbol_index, record_offset, payload_offset, length, tag16, is_parity, stripe_index, data_bytes)
        symbol_append: Callable[[int, int, int, int, bytes, bool, int, bytes], None],
        on_data_symbol: Optional[Callable[[int], None]] = None,
    ) -> None:
        self.fh = fh
        self.encryptor = encryptor
        self.symbol_size = symbol_size
        self.lrp_enabled = lrp_enabled
        self.lrp_k = lrp_k
        self.next_symbol_index = next_symbol_index
        self.next_stripe_index = next_stripe_index
        self.symbol_append = symbol_append
        self.on_data_symbol = on_data_symbol
        self._pending: List[Tuple[int, bytes]] = []

    def _flush_lrp(self, *, force: bool = False):
        if not self.lrp_enabled or not self._pending:
            return
        if not force and len(self._pending) != self.lrp_k:
            return
        stripe_idx = self.next_stripe_index
        self.next_stripe_index += 1
        pbuf = bytearray(self.symbol_size)
        for _, sbytes in self._pending:
            for i, b in enumerate(sbytes):
                pbuf[i] ^= b
        pbytes = bytes(pbuf)
        ptag = blake2s_16(pbytes)
        hdr = build_chunk_header_ext(0, stripe_idx, self.symbol_size, CODEC_LRP_PARITY, ptag)
        rflags = RFLAG_CHUNK_TAG_PRESENT | RFLAG_PARITY_RECORD
        record_offset, payload_offset, final_payload = write_record(
            self.fh, RTYPE_CHUNK, rflags, hdr, pbytes, encryptor=self.encryptor
        )
        sym_index = self.next_symbol_index
        self.next_symbol_index += 1
        self.symbol_append(sym_index, record_offset, payload_offset, len(final_payload), ptag, True, stripe_idx, final_payload)
        self._pending.clear()

    def finalize(self):
        if self.lrp_enabled and self._pending:
            # Flush partial stripe as parity over remaining data symbols
            self._flush_lrp(force=True)


def emit_file_chunks(
    ctx: ChunkEmitContext,
    *,
    entry_id: int,
    fs_path: str,
    codec_id: int,
    chunk_size: int,
) -> Tuple[List[Dict], bytes]:
    chunks: List[Dict] = []
    codec = Codec(codec_id)
    hasher = hashlib.blake2s()
    with open(fs_path, "rb") as rf:
        idx = 0
        while True:
            raw = rf.read(chunk_size)
            if not raw:
                break
            hasher.update(raw)
            enc = codec.compress(raw)
            tag16 = blake2s_16(raw)
            hdr = build_chunk_header_ext(entry_id, idx, len(raw), codec_id, tag16)
            rflags = RFLAG_CHUNK_TAG_PRESENT
            record_offset, payload_offset, final_payload = write_record(
                ctx.fh, RTYPE_CHUNK, rflags, hdr, enc, encryptor=ctx.encryptor
            )
            chunks.append(
                {
                    "offset": record_offset,
                    "payload_offset": payload_offset,
                    "payload_len": len(final_payload),
                    "uncompressed_len": len(raw),
                    "chunk_index": idx,
                    "blake2s_16": tag16,
                }
            )
            # symbolize storage payload into symbols of symbol_size
            pos = 0
            while pos < len(final_payload):
                seg = final_payload[pos : pos + ctx.symbol_size]
                sym_index = ctx.next_symbol_index
                ctx.next_symbol_index += 1
                seg_tag = blake2s_16(seg)
                ctx.symbol_append(
                    sym_index,
                    record_offset,
                    payload_offset + pos,
                    len(seg),
                    seg_tag,
                    False,
                    -1,
                    bytes(seg),
                )
                ctx._pending.append((sym_index, bytes(seg)))
                if ctx.on_data_symbol:
                    ctx.on_data_symbol(len(seg))
                ctx._flush_lrp(force=False)
                pos += len(seg)
            idx += 1
    return chunks, hasher.digest()

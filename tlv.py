from __future__ import annotations

"""
Minimal TLV encoder/decoder for Amber index and anchor payloads.

Encoding
- TLV: varint(tag) || varint(length) || payload
- Integers: unsigned LEB128 varint
- Bytes: raw payload (length provided by TLV len)
- Strings: UTF-8 bytes (length provided by TLV len)

Top-level Index tags
- 1: version (payload: varint major || varint minor)
- 2: archive_uuid (bytes[16])
- 3: writer_info (utf8)
- 4: default_chunk_size (varint)
- 5: default_codec (varint)
- 6: entries (container; contains entry TLVs, tag=1 per entry)
- 7: ecc_groups (container; contains group TLVs, tag=1 per group)
- 8: anchors (container; contains anchor-meta TLVs, tag=1 per meta)

Entry (within entries container; tag=1)
- 1: entry_id (varint)
- 2: kind (varint)
- 3: path (utf8)
- 4: mode (varint)
- 5: mtime (payload: varint sec || varint nsec)
- 6: atime (payload: varint sec || varint nsec)
- 7: size (varint, for files)
- 8: file_codec (varint)
- 9: chunk_size (varint)
- 10: symlink_target (utf8)
- 11: chunks (container; contains chunk TLVs, tag=1 per chunk)
- 12: file_blake2s_32 (bytes[32], optional)

Chunk (within chunks container; tag=1)
- 1: offset (varint)
- 2: payload_offset (varint)
- 3: payload_len (varint)
- 4: uncompressed_len (varint)
- 5: chunk_index (varint)
- 6: blake2s_16 (bytes[16])

ECC Group (within ecc_groups container; tag=1)
- 1: group_id (varint)
- 2: symbol_size (varint)
- 3: lrp (payload: varint k || varint p)
- 4: rx (container)
- 5: symbols (container; contains symbol TLVs, tag=1 per symbol)
- 6: stripes (container; contains stripe TLVs, tag=1 per stripe)

RX (within group; tag=4 container)
- 1: seed_base (bytes[16])
- 2: epsilon_ppm (varint)
- 3: parity (container; contains parity TLVs, tag=1 per parity)

RX Parity (within parity container; tag=1)
- 1: symbol_index (varint)
- 2: seed_id (varint)
- 3: offset (varint)
- 4: length (varint)
- 5: tag16 (bytes[16])
- 6: seed_base (bytes[16], optional)

Symbol (within symbols container; tag=1)
- 1: symbol_index (varint)
- 2: offset (varint)
- 3: length (varint)
- 4: tag16 (bytes[16])
- 5: stripe_index (varint)
- 6: is_parity (varint 0/1)
- 7: record_offset (varint)
- 8: seed_base (bytes[16], optional)

Stripe (within stripes container; tag=1)
- 1: stripe_index (varint)
- 2: data_symbol (varint) — may repeat
- 3: parity_symbol (varint)

Anchor record payload (separate TLV message)
- 1: version (varint)
- 2: symbol_size (varint)
- 3: merkle_root (bytes[32])
- 4: seed_base (bytes[16])
- 5: symbols (container; contains anchor-symbol TLVs, tag=1 per symbol)

Anchor symbol (within anchor symbols container; tag=1)
- 1: symbol_index (varint)
- 2: offset (varint)
- 3: length (varint)
- 4: tag16 (bytes[16])
- 5: is_parity (varint 0/1)
- 6: record_offset (varint)
- 7: seed_base (bytes[16], optional)
"""

from typing import Dict, List, Tuple, Optional


def _varint_encode(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint: negative not supported")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _varint_decode(data: bytes, pos: int) -> Tuple[int, int]:
    shift = 0
    result = 0
    while True:
        if pos >= len(data):
            raise ValueError("varint: truncated")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint: too large")


def _tlv(tag: int, payload: bytes) -> bytes:
    return _varint_encode(tag) + _varint_encode(len(payload)) + payload


def _encode_str(s: str) -> bytes:
    return s.encode("utf-8")


def _decode_str(b: bytes) -> str:
    return b.decode("utf-8")


def _iter_tlvs(data: bytes) -> List[Tuple[int, bytes]]:
    items: List[Tuple[int, bytes]] = []
    pos = 0
    n = len(data)
    while pos < n:
        tag, pos = _varint_decode(data, pos)
        ln, pos = _varint_decode(data, pos)
        if ln < 0 or pos + ln > n:
            raise ValueError("TLV length out of range")
        items.append((tag, data[pos : pos + ln]))
        pos += ln
    return items


def dumps_index(idx: Dict) -> bytes:
    out = bytearray()
    ver = idx.get("version", {})
    out += _tlv(1, _varint_encode(int(ver.get("major", 0))) + _varint_encode(int(ver.get("minor", 0))))
    uuid = idx.get("archive_uuid", b"")
    if uuid:
        out += _tlv(2, bytes(uuid))
    winfo = idx.get("writer_info")
    if winfo:
        out += _tlv(3, _encode_str(str(winfo)))
    dcs = idx.get("default_chunk_size")
    if dcs is not None:
        out += _tlv(4, _varint_encode(int(dcs)))
    dcodec = idx.get("default_codec")
    if dcodec is not None:
        out += _tlv(5, _varint_encode(int(dcodec)))

    # entries
    entries_payload = bytearray()
    for ent in idx.get("entries", []):
        e_payload = bytearray()
        e_payload += _tlv(1, _varint_encode(int(ent["entry_id"])))
        e_payload += _tlv(2, _varint_encode(int(ent["kind"])))
        e_payload += _tlv(3, _encode_str(str(ent["path"])))
        if "mode" in ent and ent["mode"] is not None:
            e_payload += _tlv(4, _varint_encode(int(ent["mode"])))
        if "mtime" in ent and isinstance(ent["mtime"], dict):
            mt = ent["mtime"]
            e_payload += _tlv(5, _varint_encode(int(mt.get("sec", 0))) + _varint_encode(int(mt.get("nsec", 0))))
        if "atime" in ent and isinstance(ent["atime"], dict):
            at = ent["atime"]
            e_payload += _tlv(6, _varint_encode(int(at.get("sec", 0))) + _varint_encode(int(at.get("nsec", 0))))
        if ent.get("kind") == 0:
            e_payload += _tlv(7, _varint_encode(int(ent.get("size", 0))))
            e_payload += _tlv(8, _varint_encode(int(ent.get("file_codec", 0))))
            e_payload += _tlv(9, _varint_encode(int(ent.get("chunk_size", 0))))
            # chunks
            chunks_payload = bytearray()
            for ch in ent.get("chunks", []):
                ch_payload = bytearray()
                ch_payload += _tlv(1, _varint_encode(int(ch.get("offset", 0))))
                ch_payload += _tlv(2, _varint_encode(int(ch.get("payload_offset", 0))))
                ch_payload += _tlv(3, _varint_encode(int(ch.get("payload_len", 0))))
                ch_payload += _tlv(4, _varint_encode(int(ch.get("uncompressed_len", 0))))
                ch_payload += _tlv(5, _varint_encode(int(ch.get("chunk_index", 0))))
                tag16 = ch.get("blake2s_16", b"")
                if tag16:
                    ch_payload += _tlv(6, bytes(tag16))
                chunks_payload += _tlv(1, bytes(ch_payload))
            if chunks_payload:
                e_payload += _tlv(11, bytes(chunks_payload))
            if "file_blake2s_32" in ent and ent["file_blake2s_32"]:
                e_payload += _tlv(12, bytes(ent["file_blake2s_32"]))
        if ent.get("kind") == 2 and ent.get("symlink_target") is not None:
            e_payload += _tlv(10, _encode_str(str(ent.get("symlink_target"))))
        entries_payload += _tlv(1, bytes(e_payload))
    if entries_payload:
        out += _tlv(6, bytes(entries_payload))

    # ecc group(s) — assume at most one, but support multiple
    eg_payload = bytearray()
    for g in idx.get("ecc_groups", []):
        gp = bytearray()
        if "group_id" in g:
            gp += _tlv(1, _varint_encode(int(g.get("group_id", 0))))
        gp += _tlv(2, _varint_encode(int(g.get("symbol_size", 0))))
        lrp = g.get("lrp") or {"k": 0, "p": 0}
        gp += _tlv(3, _varint_encode(int(lrp.get("k", 0))) + _varint_encode(int(lrp.get("p", 0))))
        rx = g.get("rx") or {}
        rx_cont = bytearray()
        if rx.get("seed_base"):
            rx_cont += _tlv(1, bytes(rx.get("seed_base")))
        # epsilon_ppm remains for parity density
        rx_cont += _tlv(2, _varint_encode(int(rx.get("epsilon_ppm", 0))))
        par_payload = bytearray()
        for p in rx.get("parity", []):
            pp = bytearray()
            pp += _tlv(1, _varint_encode(int(p.get("symbol_index", 0))))
            pp += _tlv(2, _varint_encode(int(p.get("seed_id", 0))))
            pp += _tlv(3, _varint_encode(int(p.get("offset", 0))))
            pp += _tlv(4, _varint_encode(int(p.get("length", 0))))
            if p.get("tag16"):
                pp += _tlv(5, bytes(p.get("tag16")))
            if p.get("seed_base"):
                pp += _tlv(6, bytes(p.get("seed_base")))
            par_payload += _tlv(1, bytes(pp))
        if par_payload:
            rx_cont += _tlv(3, bytes(par_payload))
        gp += _tlv(4, bytes(rx_cont))
        # symbols
        syms_payload = bytearray()
        for s in g.get("symbols", []):
            sp = bytearray()
            sp += _tlv(1, _varint_encode(int(s.get("symbol_index", 0))))
            sp += _tlv(2, _varint_encode(int(s.get("offset", 0))))
            sp += _tlv(3, _varint_encode(int(s.get("length", 0))))
            if s.get("tag16"):
                sp += _tlv(4, bytes(s.get("tag16")))
            si = int(s.get("stripe_index", -1))
            if si >= 0:
                sp += _tlv(5, _varint_encode(si))
            sp += _tlv(6, _varint_encode(1 if s.get("is_parity") else 0))
            sp += _tlv(7, _varint_encode(int(s.get("record_offset", 0))))
            if s.get("seed_base"):
                sp += _tlv(8, bytes(s.get("seed_base")))
            syms_payload += _tlv(1, bytes(sp))
        if syms_payload:
            gp += _tlv(5, bytes(syms_payload))
        # stripes
        stripes_payload = bytearray()
        for st in g.get("stripes", []):
            stp = bytearray()
            stp += _tlv(1, _varint_encode(int(st.get("stripe_index", 0))))
            for ds in st.get("data_symbols", []):
                stp += _tlv(2, _varint_encode(int(ds)))
            stp += _tlv(3, _varint_encode(int(st.get("parity_symbol", 0))))
            stripes_payload += _tlv(1, bytes(stp))
        if stripes_payload:
            gp += _tlv(6, bytes(stripes_payload))
        eg_payload += _tlv(1, bytes(gp))
    if eg_payload:
        out += _tlv(7, bytes(eg_payload))

    # anchors meta
    anc_payload = bytearray()
    for am in idx.get("anchors", []):
        ap = bytearray()
        ap += _tlv(1, _varint_encode(int(am.get("offset", 0))))
        ap += _tlv(2, _varint_encode(int(am.get("symbol_count", 0))))
        ap += _tlv(3, _varint_encode(int(am.get("first_symbol", 0))))
        ap += _tlv(4, _varint_encode(int(am.get("last_symbol", 0))))
        anc_payload += _tlv(1, bytes(ap))
    if anc_payload:
        out += _tlv(8, bytes(anc_payload))

    return bytes(out)


def loads_index(data: bytes, *, limits: Optional[Dict[str, int]] = None) -> Dict:
    """Parse index TLV with optional safety limits.

    limits keys (optional):
      - max_entries
      - max_total_chunks
      - max_symbols
      - max_rx_parity
      - max_stripes
    """
    if limits is None:
        limits = {}
    max_entries = int(limits.get("max_entries", 1_000_000))
    max_total_chunks = int(limits.get("max_total_chunks", 5_000_000))
    max_symbols = int(limits.get("max_symbols", 5_000_000))
    max_rx_parity = int(limits.get("max_rx_parity", 5_000_000))
    max_stripes = int(limits.get("max_stripes", 5_000_000))
    idx: Dict = {}
    entries: List[Dict] = []
    ecc_groups: List[Dict] = []
    anchors: List[Dict] = []
    total_chunks = 0
    for tag, payload in _iter_tlvs(data):
        if tag == 1:  # version
            pos = 0
            major, pos = _varint_decode(payload, pos)
            minor, pos = _varint_decode(payload, pos)
            idx["version"] = {"major": major, "minor": minor}
        elif tag == 2:
            idx["archive_uuid"] = payload
        elif tag == 3:
            idx["writer_info"] = _decode_str(payload)
        elif tag == 4:
            v, _ = _varint_decode(payload, 0)
            idx["default_chunk_size"] = v
        elif tag == 5:
            v, _ = _varint_decode(payload, 0)
            idx["default_codec"] = v
        elif tag == 6:  # entries container
            for etag, epl in _iter_tlvs(payload):
                if etag != 1:
                    continue
                ent: Dict = {}
                if len(entries) >= max_entries:
                    raise ValueError("Index exceeds max entries limit")
                for ft, fv in _iter_tlvs(epl):
                    if ft == 1:
                        ent["entry_id"], _ = _varint_decode(fv, 0)
                    elif ft == 2:
                        ent["kind"], _ = _varint_decode(fv, 0)
                    elif ft == 3:
                        ent["path"] = _decode_str(fv)
                    elif ft == 4:
                        ent["mode"], _ = _varint_decode(fv, 0)
                    elif ft == 5:
                        s, pos = _varint_decode(fv, 0)
                        ns, pos = _varint_decode(fv, pos)
                        ent["mtime"] = {"sec": s, "nsec": ns}
                    elif ft == 6:
                        s, pos = _varint_decode(fv, 0)
                        ns, pos = _varint_decode(fv, pos)
                        ent["atime"] = {"sec": s, "nsec": ns}
                    elif ft == 7:
                        ent["size"], _ = _varint_decode(fv, 0)
                    elif ft == 8:
                        ent["file_codec"], _ = _varint_decode(fv, 0)
                    elif ft == 9:
                        ent["chunk_size"], _ = _varint_decode(fv, 0)
                    elif ft == 10:
                        ent["symlink_target"] = _decode_str(fv)
                    elif ft == 11:  # chunks
                        chunks: List[Dict] = []
                        for ctag, cv in _iter_tlvs(fv):
                            if ctag != 1:
                                continue
                            ch: Dict = {}
                            for ct, cp in _iter_tlvs(cv):
                                if ct == 1:
                                    ch["offset"], _ = _varint_decode(cp, 0)
                                elif ct == 2:
                                    ch["payload_offset"], _ = _varint_decode(cp, 0)
                                elif ct == 3:
                                    ch["payload_len"], _ = _varint_decode(cp, 0)
                                elif ct == 4:
                                    ch["uncompressed_len"], _ = _varint_decode(cp, 0)
                                elif ct == 5:
                                    ch["chunk_index"], _ = _varint_decode(cp, 0)
                                elif ct == 6:
                                    ch["blake2s_16"] = cp
                            chunks.append(ch)
                            total_chunks += 1
                            if total_chunks > max_total_chunks:
                                raise ValueError("Index exceeds max total chunks limit")
                        ent["chunks"] = chunks
                    elif ft == 12:
                        ent["file_blake2s_32"] = fv
                entries.append(ent)
        elif tag == 7:  # ecc groups container
            for gtag, gpl in _iter_tlvs(payload):
                if gtag != 1:
                    continue
                g: Dict = {}
                syms: List[Dict] = []
                stripes: List[Dict] = []
                rx_container: Dict = {"parity": []}
                for gt, gv in _iter_tlvs(gpl):
                    if gt == 1:
                        g["group_id"], _ = _varint_decode(gv, 0)
                    elif gt == 2:
                        g["symbol_size"], _ = _varint_decode(gv, 0)
                    elif gt == 3:
                        k, pos = _varint_decode(gv, 0)
                        p, pos = _varint_decode(gv, pos)
                        g["lrp"] = {"k": k, "p": p}
                    elif gt == 4:  # rx
                        rx_local: Dict = {"parity": []}
                        for rt, rv in _iter_tlvs(gv):
                            if rt == 1:
                                rx_local["seed_base"] = rv
                            elif rt == 2:
                                rx_local["epsilon_ppm"], _ = _varint_decode(rv, 0)
                            elif rt == 3:
                                plist: List[Dict] = []
                                for pt, pv in _iter_tlvs(rv):
                                    if pt != 1:
                                        continue
                                    pd: Dict = {}
                                    for ft, fv in _iter_tlvs(pv):
                                        if ft == 1:
                                            pd["symbol_index"], _ = _varint_decode(fv, 0)
                                        elif ft == 2:
                                            pd["seed_id"], _ = _varint_decode(fv, 0)
                                        elif ft == 3:
                                            pd["offset"], _ = _varint_decode(fv, 0)
                                        elif ft == 4:
                                            pd["length"], _ = _varint_decode(fv, 0)
                                        elif ft == 5:
                                            pd["tag16"] = fv
                                        elif ft == 6:
                                            pd["seed_base"] = fv
                                    plist.append(pd)
                                    if len(plist) > max_rx_parity:
                                        raise ValueError("Index exceeds max RX parity limit")
                                rx_local["parity"] = plist
                        rx_container = rx_local
                    elif gt == 5:  # symbols
                        for st, sv in _iter_tlvs(gv):
                            if st != 1:
                                continue
                            sd: Dict = {}
                            for ft, fv in _iter_tlvs(sv):
                                if ft == 1:
                                    sd["symbol_index"], _ = _varint_decode(fv, 0)
                                elif ft == 2:
                                    sd["offset"], _ = _varint_decode(fv, 0)
                                elif ft == 3:
                                    sd["length"], _ = _varint_decode(fv, 0)
                                elif ft == 4:
                                    sd["tag16"] = fv
                                elif ft == 5:
                                    sd["stripe_index"], _ = _varint_decode(fv, 0)
                                elif ft == 6:
                                    v, _ = _varint_decode(fv, 0)
                                    sd["is_parity"] = bool(v)
                                elif ft == 7:
                                    sd["record_offset"], _ = _varint_decode(fv, 0)
                                elif ft == 8:
                                    sd["seed_base"] = fv
                            syms.append(sd)
                            if len(syms) > max_symbols:
                                raise ValueError("Index exceeds max symbols limit")
                    elif gt == 6:  # stripes
                        for st, sv in _iter_tlvs(gv):
                            if st != 1:
                                continue
                            sd: Dict = {"data_symbols": []}
                            for ft, fv in _iter_tlvs(sv):
                                if ft == 1:
                                    sd["stripe_index"], _ = _varint_decode(fv, 0)
                                elif ft == 2:
                                    v, _ = _varint_decode(fv, 0)
                                    sd.setdefault("data_symbols", []).append(v)
                                elif ft == 3:
                                    sd["parity_symbol"], _ = _varint_decode(fv, 0)
                            stripes.append(sd)
                            if len(stripes) > max_stripes:
                                raise ValueError("Index exceeds max stripes limit")
                g["symbols"] = syms
                g["stripes"] = stripes
                g["rx"] = rx_container
                ecc_groups.append(g)
        elif tag == 8:  # anchors meta
            for at, av in _iter_tlvs(payload):
                if at != 1:
                    continue
                am: Dict = {}
                for ft, fv in _iter_tlvs(av):
                    if ft == 1:
                        am["offset"], _ = _varint_decode(fv, 0)
                    elif ft == 2:
                        am["symbol_count"], _ = _varint_decode(fv, 0)
                    elif ft == 3:
                        am["first_symbol"], _ = _varint_decode(fv, 0)
                    elif ft == 4:
                        am["last_symbol"], _ = _varint_decode(fv, 0)
                anchors.append(am)

    if entries:
        idx["entries"] = entries
    if ecc_groups:
        idx["ecc_groups"] = ecc_groups
    if anchors:
        idx["anchors"] = anchors
    return idx


def dumps_anchor(anchor: Dict) -> bytes:
    out = bytearray()
    out += _tlv(1, _varint_encode(int(anchor.get("version", 1))))
    out += _tlv(2, _varint_encode(int(anchor.get("symbol_size", 0))))
    if anchor.get("merkle_root"):
        out += _tlv(3, bytes(anchor.get("merkle_root")))
    if anchor.get("seed_base"):
        out += _tlv(4, bytes(anchor.get("seed_base")))
    syms = anchor.get("symbols", [])
    if syms:
        sp = bytearray()
        for s in syms:
            sb = bytearray()
            sb += _tlv(1, _varint_encode(int(s.get("symbol_index", 0))))
            sb += _tlv(2, _varint_encode(int(s.get("offset", 0))))
            sb += _tlv(3, _varint_encode(int(s.get("length", 0))))
            if s.get("tag16"):
                sb += _tlv(4, bytes(s.get("tag16")))
            sb += _tlv(5, _varint_encode(1 if s.get("is_parity") else 0))
            sb += _tlv(6, _varint_encode(int(s.get("record_offset", 0))))
            if s.get("seed_base"):
                sb += _tlv(7, bytes(s.get("seed_base")))
            sp += _tlv(1, bytes(sb))
        out += _tlv(5, bytes(sp))
    return bytes(out)


def loads_anchor(data: bytes, *, max_symbols: int = 1024) -> Dict:
    a: Dict = {}
    syms: List[Dict] = []
    for tag, payload in _iter_tlvs(data):
        if tag == 1:
            a["version"], _ = _varint_decode(payload, 0)
        elif tag == 2:
            a["symbol_size"], _ = _varint_decode(payload, 0)
        elif tag == 3:
            a["merkle_root"] = payload
        elif tag == 4:
            a["seed_base"] = payload
        elif tag == 5:
            count = 0
            for st, sv in _iter_tlvs(payload):
                if st != 1:
                    continue
                sd: Dict = {}
                for ft, fv in _iter_tlvs(sv):
                    if ft == 1:
                        sd["symbol_index"], _ = _varint_decode(fv, 0)
                    elif ft == 2:
                        sd["offset"], _ = _varint_decode(fv, 0)
                    elif ft == 3:
                        sd["length"], _ = _varint_decode(fv, 0)
                    elif ft == 4:
                        sd["tag16"] = fv
                    elif ft == 5:
                        v, _ = _varint_decode(fv, 0)
                        sd["is_parity"] = bool(v)
                    elif ft == 6:
                        sd["record_offset"], _ = _varint_decode(fv, 0)
                    elif ft == 7:
                        sd["seed_base"] = fv
                syms.append(sd)
                count += 1
                if count > max_symbols:
                    raise ValueError("Anchor exceeds max symbols limit")
    if syms:
        a["symbols"] = syms
    return a

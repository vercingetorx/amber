use std::collections::BTreeMap;

use crate::error::{AmberError, AmberResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlvValue {
    U64(u64),
    Bool(bool),
    Bytes(Vec<u8>),
    String(String),
    Map(TlvMap),
    List(Vec<TlvMap>),
}

pub type TlvMap = BTreeMap<String, TlvValue>;

#[derive(Clone, Copy, Debug)]
pub struct IndexLimits {
    pub max_entries: usize,
    pub max_total_chunks: usize,
    pub max_ecc_groups: usize,
    pub max_symbols: usize,
    pub max_total_symbols: usize,
    pub max_amcf_parity: usize,
    pub max_total_amcf_parity: usize,
    pub max_total_anchors: usize,
    pub max_total_segments: usize,
}

impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_total_chunks: 5_000_000,
            max_ecc_groups: 100_000,
            max_symbols: 5_000_000,
            max_total_symbols: 5_000_000,
            max_amcf_parity: 5_000_000,
            max_total_amcf_parity: 5_000_000,
            max_total_anchors: 100_000,
            max_total_segments: 100_000,
        }
    }
}

pub fn dumps_index(idx: &TlvMap) -> AmberResult<Vec<u8>> {
    let mut out = Vec::new();
    let version = get_map(idx, "version");
    let major = version.and_then(|map| get_u64(map, "major")).unwrap_or(0);
    let minor = version.and_then(|map| get_u64(map, "minor")).unwrap_or(0);
    out.extend(tlv(
        1,
        &[varint_encode(major), varint_encode(minor)].concat(),
    )?);

    if let Some(uuid) = get_bytes(idx, "archive_uuid") {
        require_nonempty_bytes("archive_uuid", uuid)?;
        out.extend(tlv(2, uuid)?);
    }
    if let Some(writer_info) = get_string(idx, "writer_info") {
        if !writer_info.is_empty() {
            out.extend(tlv(3, writer_info.as_bytes())?);
        }
    }
    if let Some(value) = get_u64(idx, "default_chunk_size") {
        out.extend(tlv(4, &varint_encode(value))?);
    }
    if let Some(value) = get_u64(idx, "default_codec") {
        out.extend(tlv(5, &varint_encode(value))?);
    }

    let mut entries_payload = Vec::new();
    if let Some(entries) = get_list(idx, "entries") {
        for ent in entries {
            let mut e_payload = Vec::new();
            e_payload.extend(tlv(1, &varint_encode(req_u64(ent, "entry_id")?))?);
            e_payload.extend(tlv(2, &varint_encode(req_u64(ent, "kind")?))?);
            e_payload.extend(tlv(3, req_string(ent, "path")?.as_bytes())?);
            if let Some(value) = get_u64(ent, "mode") {
                e_payload.extend(tlv(4, &varint_encode(value))?);
            }
            if let Some(mtime) = get_map(ent, "mtime") {
                e_payload.extend(tlv(
                    5,
                    &[
                        varint_encode(get_u64(mtime, "sec").unwrap_or(0)),
                        varint_encode(get_u64(mtime, "nsec").unwrap_or(0)),
                    ]
                    .concat(),
                )?);
            }
            if let Some(atime) = get_map(ent, "atime") {
                e_payload.extend(tlv(
                    6,
                    &[
                        varint_encode(get_u64(atime, "sec").unwrap_or(0)),
                        varint_encode(get_u64(atime, "nsec").unwrap_or(0)),
                    ]
                    .concat(),
                )?);
            }
            if get_u64(ent, "kind").unwrap_or(0) == 0 {
                e_payload.extend(tlv(7, &varint_encode(get_u64(ent, "size").unwrap_or(0)))?);
                if let Some(file_codec) = get_u64(ent, "file_codec") {
                    e_payload.extend(tlv(8, &varint_encode(file_codec))?);
                }
                if let Some(chunk_size) = get_u64(ent, "chunk_size") {
                    e_payload.extend(tlv(9, &varint_encode(chunk_size))?);
                }
                let mut chunks_payload = Vec::new();
                if let Some(chunks) = get_list(ent, "chunks") {
                    for ch in chunks {
                        let mut ch_payload = Vec::new();
                        ch_payload
                            .extend(tlv(1, &varint_encode(get_u64(ch, "offset").unwrap_or(0)))?);
                        ch_payload.extend(tlv(
                            2,
                            &varint_encode(get_u64(ch, "payload_offset").unwrap_or(0)),
                        )?);
                        ch_payload.extend(tlv(
                            3,
                            &varint_encode(get_u64(ch, "payload_len").unwrap_or(0)),
                        )?);
                        ch_payload.extend(tlv(
                            4,
                            &varint_encode(get_u64(ch, "uncompressed_len").unwrap_or(0)),
                        )?);
                        ch_payload.extend(tlv(
                            5,
                            &varint_encode(get_u64(ch, "chunk_index").unwrap_or(0)),
                        )?);
                        if let Some(tag) = get_bytes(ch, "blake3_32") {
                            ch_payload.extend(tlv(6, tag)?);
                        }
                        chunks_payload.extend(tlv(1, &ch_payload)?);
                    }
                }
                if !chunks_payload.is_empty() {
                    e_payload.extend(tlv(11, &chunks_payload)?);
                }
                if let Some(tag) = get_bytes(ent, "file_blake3_32") {
                    if !tag.is_empty() {
                        e_payload.extend(tlv(12, tag)?);
                    }
                }
            }
            if get_u64(ent, "kind").unwrap_or(0) == 2 {
                if let Some(target) = get_string(ent, "symlink_target") {
                    e_payload.extend(tlv(10, target.as_bytes())?);
                }
            }
            entries_payload.extend(tlv(1, &e_payload)?);
        }
    }
    if !entries_payload.is_empty() {
        out.extend(tlv(6, &entries_payload)?);
    }

    let mut ecc_groups_payload = Vec::new();
    if let Some(groups) = get_list(idx, "ecc_groups") {
        for group in groups {
            let mut group_payload = Vec::new();
            if let Some(value) = get_u64(group, "group_id") {
                group_payload.extend(tlv(1, &varint_encode(value))?);
            }
            group_payload.extend(tlv(
                2,
                &varint_encode(get_u64(group, "symbol_size").unwrap_or(0)),
            )?);
            let amcf = get_map(group, "amcf");
            let mut amcf_payload = Vec::new();
            if let Some(amcf) = amcf {
                if let Some(seed_base) = get_bytes(amcf, "seed_base") {
                    require_nonempty_bytes("ecc_groups.amcf.seed_base", seed_base)?;
                    amcf_payload.extend(tlv(1, seed_base)?);
                }
                amcf_payload.extend(tlv(
                    2,
                    &varint_encode(get_u64(amcf, "epsilon_ppm").unwrap_or(0)),
                )?);
                if let Some(scheme) = get_string(amcf, "scheme") {
                    if !scheme.is_empty() {
                        amcf_payload.extend(tlv(7, scheme.as_bytes())?);
                    }
                }
                let mut parity_payload = Vec::new();
                if let Some(parity_list) = get_list(amcf, "parity") {
                    for parity in parity_list {
                        let mut pp = Vec::new();
                        pp.extend(tlv(
                            1,
                            &varint_encode(get_u64(parity, "symbol_index").unwrap_or(0)),
                        )?);
                        pp.extend(tlv(
                            2,
                            &varint_encode(get_u64(parity, "seed_id").unwrap_or(0)),
                        )?);
                        pp.extend(tlv(
                            3,
                            &varint_encode(get_u64(parity, "offset").unwrap_or(0)),
                        )?);
                        pp.extend(tlv(
                            4,
                            &varint_encode(get_u64(parity, "length").unwrap_or(0)),
                        )?);
                        if let Some(tag) = get_bytes(parity, "tag32") {
                            require_nonempty_bytes("ecc_groups.amcf.parity.tag32", tag)?;
                            pp.extend(tlv(5, tag)?);
                        }
                        if let Some(seed_base) = get_bytes(parity, "seed_base") {
                            require_nonempty_bytes("ecc_groups.amcf.parity.seed_base", seed_base)?;
                            pp.extend(tlv(6, seed_base)?);
                        }
                        if let Some(row_count) = get_u64(parity, "row_count") {
                            pp.extend(tlv(8, &varint_encode(row_count))?);
                        }
                        parity_payload.extend(tlv(1, &pp)?);
                    }
                }
                if !parity_payload.is_empty() {
                    amcf_payload.extend(tlv(3, &parity_payload)?);
                }
            } else {
                amcf_payload.extend(tlv(2, &varint_encode(0))?);
            }
            group_payload.extend(tlv(4, &amcf_payload)?);

            let mut symbols_payload = Vec::new();
            if let Some(symbols) = get_list(group, "symbols") {
                for symbol in symbols {
                    let mut sp = Vec::new();
                    sp.extend(tlv(
                        1,
                        &varint_encode(get_u64(symbol, "symbol_index").unwrap_or(0)),
                    )?);
                    sp.extend(tlv(
                        2,
                        &varint_encode(get_u64(symbol, "offset").unwrap_or(0)),
                    )?);
                    sp.extend(tlv(
                        3,
                        &varint_encode(get_u64(symbol, "length").unwrap_or(0)),
                    )?);
                    if let Some(tag) = get_bytes(symbol, "tag32") {
                        require_nonempty_bytes("ecc_groups.symbols.tag32", tag)?;
                        sp.extend(tlv(4, tag)?);
                    }
                    if let Some(stripe_index) = get_u64(symbol, "stripe_index") {
                        sp.extend(tlv(5, &varint_encode(stripe_index))?);
                    }
                    sp.extend(tlv(
                        6,
                        &varint_encode(if get_bool(symbol, "is_parity").unwrap_or(false) {
                            1
                        } else {
                            0
                        }),
                    )?);
                    sp.extend(tlv(
                        7,
                        &varint_encode(get_u64(symbol, "record_offset").unwrap_or(0)),
                    )?);
                    if let Some(seed_base) = get_bytes(symbol, "seed_base") {
                        require_nonempty_bytes("ecc_groups.symbols.seed_base", seed_base)?;
                        sp.extend(tlv(8, seed_base)?);
                    }
                    symbols_payload.extend(tlv(1, &sp)?);
                }
            }
            if !symbols_payload.is_empty() {
                group_payload.extend(tlv(5, &symbols_payload)?);
            }
            ecc_groups_payload.extend(tlv(1, &group_payload)?);
        }
    }
    if !ecc_groups_payload.is_empty() {
        out.extend(tlv(7, &ecc_groups_payload)?);
    }

    let mut anchors_payload = Vec::new();
    if let Some(anchors) = get_list(idx, "anchors") {
        for anchor in anchors {
            let mut ap = Vec::new();
            ap.extend(tlv(
                1,
                &varint_encode(get_u64(anchor, "offset").unwrap_or(0)),
            )?);
            ap.extend(tlv(
                2,
                &varint_encode(get_u64(anchor, "symbol_count").unwrap_or(0)),
            )?);
            ap.extend(tlv(
                3,
                &varint_encode(get_u64(anchor, "first_symbol").unwrap_or(0)),
            )?);
            ap.extend(tlv(
                4,
                &varint_encode(get_u64(anchor, "last_symbol").unwrap_or(0)),
            )?);
            anchors_payload.extend(tlv(1, &ap)?);
        }
    }
    if !anchors_payload.is_empty() {
        out.extend(tlv(8, &anchors_payload)?);
    }

    let mut segments_payload = Vec::new();
    if let Some(segments) = get_list(idx, "segments") {
        for segment in segments {
            let mut sp = Vec::new();
            sp.extend(tlv(
                1,
                &varint_encode(get_u64(segment, "segment_index").unwrap_or(0)),
            )?);
            sp.extend(tlv(
                2,
                &varint_encode(get_u64(segment, "physical_header_length").unwrap_or(0)),
            )?);
            segments_payload.extend(tlv(1, &sp)?);
        }
    }
    if !segments_payload.is_empty() {
        out.extend(tlv(9, &segments_payload)?);
    }

    Ok(out)
}

pub fn loads_index(data: &[u8], limits: IndexLimits) -> AmberResult<TlvMap> {
    let mut idx = TlvMap::new();
    let mut entries = Vec::new();
    let mut ecc_groups = Vec::new();
    let mut anchors = Vec::new();
    let mut segments = Vec::new();
    let mut total_chunks = 0usize;
    let mut total_symbols = 0usize;
    let mut total_amcf_parity = 0usize;

    for (tag, payload) in iter_tlvs(data)? {
        match tag {
            1 => {
                let (major, pos) = varint_decode(payload, 0)?;
                let (minor, _) = varint_decode(payload, pos)?;
                idx.insert(
                    "version".into(),
                    TlvValue::Map(map_of([
                        ("major", TlvValue::U64(major)),
                        ("minor", TlvValue::U64(minor)),
                    ])),
                );
            }
            2 => {
                idx.insert("archive_uuid".into(), TlvValue::Bytes(payload.to_vec()));
            }
            3 => {
                idx.insert("writer_info".into(), TlvValue::String(decode_str(payload)?));
            }
            4 => {
                idx.insert(
                    "default_chunk_size".into(),
                    TlvValue::U64(varint_decode(payload, 0)?.0),
                );
            }
            5 => {
                idx.insert(
                    "default_codec".into(),
                    TlvValue::U64(varint_decode(payload, 0)?.0),
                );
            }
            6 => {
                for (etag, epl) in iter_tlvs(payload)? {
                    if etag != 1 {
                        continue;
                    }
                    if entries.len() >= limits.max_entries {
                        return Err(AmberError::Invalid(
                            "Index exceeds max entries limit".into(),
                        ));
                    }
                    let mut ent = TlvMap::new();
                    for (ft, fv) in iter_tlvs(epl)? {
                        match ft {
                            1 => {
                                ent.insert(
                                    "entry_id".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            2 => {
                                ent.insert("kind".into(), TlvValue::U64(varint_decode(fv, 0)?.0));
                            }
                            3 => {
                                ent.insert("path".into(), TlvValue::String(decode_str(fv)?));
                            }
                            4 => {
                                ent.insert("mode".into(), TlvValue::U64(varint_decode(fv, 0)?.0));
                            }
                            5 => {
                                ent.insert("mtime".into(), TlvValue::Map(parse_time_map(fv)?));
                            }
                            6 => {
                                ent.insert("atime".into(), TlvValue::Map(parse_time_map(fv)?));
                            }
                            7 => {
                                ent.insert("size".into(), TlvValue::U64(varint_decode(fv, 0)?.0));
                            }
                            8 => {
                                ent.insert(
                                    "file_codec".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            9 => {
                                ent.insert(
                                    "chunk_size".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            10 => {
                                ent.insert(
                                    "symlink_target".into(),
                                    TlvValue::String(decode_str(fv)?),
                                );
                            }
                            11 => {
                                let mut chunks = Vec::new();
                                for (ctag, cv) in iter_tlvs(fv)? {
                                    if ctag != 1 {
                                        continue;
                                    }
                                    let mut ch = TlvMap::new();
                                    for (ct, cp) in iter_tlvs(cv)? {
                                        match ct {
                                            1 => {
                                                ch.insert(
                                                    "offset".into(),
                                                    TlvValue::U64(varint_decode(cp, 0)?.0),
                                                );
                                            }
                                            2 => {
                                                ch.insert(
                                                    "payload_offset".into(),
                                                    TlvValue::U64(varint_decode(cp, 0)?.0),
                                                );
                                            }
                                            3 => {
                                                ch.insert(
                                                    "payload_len".into(),
                                                    TlvValue::U64(varint_decode(cp, 0)?.0),
                                                );
                                            }
                                            4 => {
                                                ch.insert(
                                                    "uncompressed_len".into(),
                                                    TlvValue::U64(varint_decode(cp, 0)?.0),
                                                );
                                            }
                                            5 => {
                                                ch.insert(
                                                    "chunk_index".into(),
                                                    TlvValue::U64(varint_decode(cp, 0)?.0),
                                                );
                                            }
                                            6 => {
                                                ch.insert(
                                                    "blake3_32".into(),
                                                    TlvValue::Bytes(cp.to_vec()),
                                                );
                                            }
                                            _ => {}
                                        }
                                    }
                                    chunks.push(ch);
                                    total_chunks += 1;
                                    if total_chunks > limits.max_total_chunks {
                                        return Err(AmberError::Invalid(
                                            "Index exceeds max total chunks limit".into(),
                                        ));
                                    }
                                }
                                ent.insert("chunks".into(), TlvValue::List(chunks));
                            }
                            12 => {
                                ent.insert("file_blake3_32".into(), TlvValue::Bytes(fv.to_vec()));
                            }
                            _ => {}
                        }
                    }
                    entries.push(ent);
                }
            }
            7 => {
                for (gtag, gpl) in iter_tlvs(payload)? {
                    if gtag != 1 {
                        continue;
                    }
                    if ecc_groups.len() >= limits.max_ecc_groups {
                        return Err(AmberError::Invalid(
                            "Index exceeds max ECC groups limit".into(),
                        ));
                    }
                    let mut group = TlvMap::new();
                    let mut symbols = Vec::new();
                    let mut amcf = map_of([("parity", TlvValue::List(Vec::new()))]);
                    for (gt, gv) in iter_tlvs(gpl)? {
                        match gt {
                            1 => {
                                group.insert(
                                    "group_id".into(),
                                    TlvValue::U64(varint_decode(gv, 0)?.0),
                                );
                            }
                            2 => {
                                group.insert(
                                    "symbol_size".into(),
                                    TlvValue::U64(varint_decode(gv, 0)?.0),
                                );
                            }
                            4 => {
                                let mut local = map_of([("parity", TlvValue::List(Vec::new()))]);
                                let mut plist = Vec::new();
                                for (rt, rv) in iter_tlvs(gv)? {
                                    match rt {
                                        1 => {
                                            local.insert(
                                                "seed_base".into(),
                                                TlvValue::Bytes(rv.to_vec()),
                                            );
                                        }
                                        2 => {
                                            local.insert(
                                                "epsilon_ppm".into(),
                                                TlvValue::U64(varint_decode(rv, 0)?.0),
                                            );
                                        }
                                        7 => {
                                            local.insert(
                                                "scheme".into(),
                                                TlvValue::String(decode_str(rv)?),
                                            );
                                        }
                                        3 => {
                                            for (pt, pv) in iter_tlvs(rv)? {
                                                if pt != 1 {
                                                    continue;
                                                }
                                                let mut pd = TlvMap::new();
                                                for (ft, fv) in iter_tlvs(pv)? {
                                                    match ft {
                                                        1 => {
                                                            pd.insert(
                                                                "symbol_index".into(),
                                                                TlvValue::U64(
                                                                    varint_decode(fv, 0)?.0,
                                                                ),
                                                            );
                                                        }
                                                        2 => {
                                                            pd.insert(
                                                                "seed_id".into(),
                                                                TlvValue::U64(
                                                                    varint_decode(fv, 0)?.0,
                                                                ),
                                                            );
                                                        }
                                                        3 => {
                                                            pd.insert(
                                                                "offset".into(),
                                                                TlvValue::U64(
                                                                    varint_decode(fv, 0)?.0,
                                                                ),
                                                            );
                                                        }
                                                        4 => {
                                                            pd.insert(
                                                                "length".into(),
                                                                TlvValue::U64(
                                                                    varint_decode(fv, 0)?.0,
                                                                ),
                                                            );
                                                        }
                                                        5 => {
                                                            pd.insert(
                                                                "tag32".into(),
                                                                TlvValue::Bytes(fv.to_vec()),
                                                            );
                                                        }
                                                        6 => {
                                                            pd.insert(
                                                                "seed_base".into(),
                                                                TlvValue::Bytes(fv.to_vec()),
                                                            );
                                                        }
                                                        8 => {
                                                            pd.insert(
                                                                "row_count".into(),
                                                                TlvValue::U64(
                                                                    varint_decode(fv, 0)?.0,
                                                                ),
                                                            );
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                                plist.push(pd);
                                                if plist.len() > limits.max_amcf_parity {
                                                    return Err(AmberError::Invalid(
                                                        "Index exceeds max AMCF parity limit"
                                                            .into(),
                                                    ));
                                                }
                                                total_amcf_parity += 1;
                                                if total_amcf_parity > limits.max_total_amcf_parity
                                                {
                                                    return Err(AmberError::Invalid(
                                                        "Index exceeds max total AMCF parity limit"
                                                            .into(),
                                                    ));
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                local.insert("parity".into(), TlvValue::List(plist));
                                amcf = local;
                            }
                            5 => {
                                for (st, sv) in iter_tlvs(gv)? {
                                    if st != 1 {
                                        continue;
                                    }
                                    let mut symbol = TlvMap::new();
                                    for (ft, fv) in iter_tlvs(sv)? {
                                        match ft {
                                            1 => {
                                                symbol.insert(
                                                    "symbol_index".into(),
                                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                                );
                                            }
                                            2 => {
                                                symbol.insert(
                                                    "offset".into(),
                                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                                );
                                            }
                                            3 => {
                                                symbol.insert(
                                                    "length".into(),
                                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                                );
                                            }
                                            4 => {
                                                symbol.insert(
                                                    "tag32".into(),
                                                    TlvValue::Bytes(fv.to_vec()),
                                                );
                                            }
                                            5 => {
                                                symbol.insert(
                                                    "stripe_index".into(),
                                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                                );
                                            }
                                            6 => {
                                                symbol.insert(
                                                    "is_parity".into(),
                                                    TlvValue::Bool(varint_decode(fv, 0)?.0 != 0),
                                                );
                                            }
                                            7 => {
                                                symbol.insert(
                                                    "record_offset".into(),
                                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                                );
                                            }
                                            8 => {
                                                symbol.insert(
                                                    "seed_base".into(),
                                                    TlvValue::Bytes(fv.to_vec()),
                                                );
                                            }
                                            _ => {}
                                        }
                                    }
                                    symbols.push(symbol);
                                    if symbols.len() > limits.max_symbols {
                                        return Err(AmberError::Invalid(
                                            "Index exceeds max symbols limit".into(),
                                        ));
                                    }
                                    total_symbols += 1;
                                    if total_symbols > limits.max_total_symbols {
                                        return Err(AmberError::Invalid(
                                            "Index exceeds max total symbols limit".into(),
                                        ));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    group.insert("symbols".into(), TlvValue::List(symbols));
                    group.insert("amcf".into(), TlvValue::Map(amcf));
                    ecc_groups.push(group);
                }
            }
            8 => {
                for (at, av) in iter_tlvs(payload)? {
                    if at != 1 {
                        continue;
                    }
                    if anchors.len() >= limits.max_total_anchors {
                        return Err(AmberError::Invalid(
                            "Index exceeds max anchors limit".into(),
                        ));
                    }
                    let mut anchor = TlvMap::new();
                    for (ft, fv) in iter_tlvs(av)? {
                        match ft {
                            1 => {
                                anchor.insert(
                                    "offset".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            2 => {
                                anchor.insert(
                                    "symbol_count".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            3 => {
                                anchor.insert(
                                    "first_symbol".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            4 => {
                                anchor.insert(
                                    "last_symbol".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            _ => {}
                        }
                    }
                    anchors.push(anchor);
                }
            }
            9 => {
                for (st, sv) in iter_tlvs(payload)? {
                    if st != 1 {
                        continue;
                    }
                    if segments.len() >= limits.max_total_segments {
                        return Err(AmberError::Invalid(
                            "Index exceeds max segments limit".into(),
                        ));
                    }
                    let mut segment = TlvMap::new();
                    for (ft, fv) in iter_tlvs(sv)? {
                        match ft {
                            1 => {
                                segment.insert(
                                    "segment_index".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            2 => {
                                segment.insert(
                                    "physical_header_length".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            _ => {}
                        }
                    }
                    segments.push(segment);
                }
            }
            _ => {}
        }
    }

    if !entries.is_empty() {
        idx.insert("entries".into(), TlvValue::List(entries));
    }
    if !ecc_groups.is_empty() {
        idx.insert("ecc_groups".into(), TlvValue::List(ecc_groups));
    }
    if !anchors.is_empty() {
        idx.insert("anchors".into(), TlvValue::List(anchors));
    }
    if !segments.is_empty() {
        idx.insert("segments".into(), TlvValue::List(segments));
    }
    Ok(idx)
}

pub fn dumps_anchor(anchor: &TlvMap) -> AmberResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend(tlv(
        1,
        &varint_encode(get_u64(anchor, "version").unwrap_or(1)),
    )?);
    out.extend(tlv(
        2,
        &varint_encode(get_u64(anchor, "symbol_size").unwrap_or(0)),
    )?);
    if let Some(root) = get_bytes(anchor, "merkle_root") {
        require_nonempty_bytes("anchor.merkle_root", root)?;
        out.extend(tlv(3, root)?);
    }
    if let Some(seed_base) = get_bytes(anchor, "seed_base") {
        require_nonempty_bytes("anchor.seed_base", seed_base)?;
        out.extend(tlv(4, seed_base)?);
    }
    if let Some(scheme) = get_string(anchor, "scheme") {
        if !scheme.is_empty() {
            out.extend(tlv(6, scheme.as_bytes())?);
        }
    }
    let mut syms_payload = Vec::new();
    if let Some(symbols) = get_list(anchor, "symbols") {
        for symbol in symbols {
            let mut sb = Vec::new();
            sb.extend(tlv(
                1,
                &varint_encode(get_u64(symbol, "symbol_index").unwrap_or(0)),
            )?);
            sb.extend(tlv(
                2,
                &varint_encode(get_u64(symbol, "offset").unwrap_or(0)),
            )?);
            sb.extend(tlv(
                3,
                &varint_encode(get_u64(symbol, "length").unwrap_or(0)),
            )?);
            if let Some(tag) = get_bytes(symbol, "tag32") {
                require_nonempty_bytes("anchor.symbols.tag32", tag)?;
                sb.extend(tlv(4, tag)?);
            }
            sb.extend(tlv(
                5,
                &varint_encode(if get_bool(symbol, "is_parity").unwrap_or(false) {
                    1
                } else {
                    0
                }),
            )?);
            sb.extend(tlv(
                6,
                &varint_encode(get_u64(symbol, "record_offset").unwrap_or(0)),
            )?);
            if let Some(seed_base) = get_bytes(symbol, "seed_base") {
                require_nonempty_bytes("anchor.symbols.seed_base", seed_base)?;
                sb.extend(tlv(7, seed_base)?);
            }
            syms_payload.extend(tlv(1, &sb)?);
        }
    }
    if !syms_payload.is_empty() {
        out.extend(tlv(5, &syms_payload)?);
    }
    Ok(out)
}

pub fn loads_anchor(data: &[u8], max_symbols: usize) -> AmberResult<TlvMap> {
    let mut anchor = TlvMap::new();
    let mut symbols = Vec::new();
    for (tag, payload) in iter_tlvs(data)? {
        match tag {
            1 => {
                anchor.insert(
                    "version".into(),
                    TlvValue::U64(varint_decode(payload, 0)?.0),
                );
            }
            2 => {
                anchor.insert(
                    "symbol_size".into(),
                    TlvValue::U64(varint_decode(payload, 0)?.0),
                );
            }
            3 => {
                anchor.insert("merkle_root".into(), TlvValue::Bytes(payload.to_vec()));
            }
            4 => {
                anchor.insert("seed_base".into(), TlvValue::Bytes(payload.to_vec()));
            }
            5 => {
                let mut count = 0usize;
                for (st, sv) in iter_tlvs(payload)? {
                    if st != 1 {
                        continue;
                    }
                    let mut symbol = TlvMap::new();
                    for (ft, fv) in iter_tlvs(sv)? {
                        match ft {
                            1 => {
                                symbol.insert(
                                    "symbol_index".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            2 => {
                                symbol.insert(
                                    "offset".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            3 => {
                                symbol.insert(
                                    "length".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            4 => {
                                symbol.insert("tag32".into(), TlvValue::Bytes(fv.to_vec()));
                            }
                            5 => {
                                symbol.insert(
                                    "is_parity".into(),
                                    TlvValue::Bool(varint_decode(fv, 0)?.0 != 0),
                                );
                            }
                            6 => {
                                symbol.insert(
                                    "record_offset".into(),
                                    TlvValue::U64(varint_decode(fv, 0)?.0),
                                );
                            }
                            7 => {
                                symbol.insert("seed_base".into(), TlvValue::Bytes(fv.to_vec()));
                            }
                            _ => {}
                        }
                    }
                    symbols.push(symbol);
                    count += 1;
                    if count > max_symbols {
                        return Err(AmberError::Invalid(
                            "Anchor exceeds max symbols limit".into(),
                        ));
                    }
                }
            }
            6 => {
                anchor.insert("scheme".into(), TlvValue::String(decode_str(payload)?));
            }
            _ => {}
        }
    }
    if !symbols.is_empty() {
        anchor.insert("symbols".into(), TlvValue::List(symbols));
    }
    Ok(anchor)
}

pub fn varint_encode(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
            out.push(b);
        } else {
            out.push(b);
            break;
        }
    }
    out
}

pub fn varint_decode(data: &[u8], mut pos: usize) -> AmberResult<(u64, usize)> {
    let mut shift = 0u32;
    let mut result = 0u64;
    loop {
        if pos >= data.len() {
            return Err(AmberError::Invalid("varint: truncated".into()));
        }
        let b = data[pos];
        pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok((result, pos));
        }
        shift += 7;
        if shift > 63 {
            return Err(AmberError::Invalid("varint: too large".into()));
        }
    }
}

pub fn tlv(tag: u64, payload: &[u8]) -> AmberResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend(varint_encode(tag));
    out.extend(varint_encode(u64::try_from(payload.len()).map_err(
        |_| AmberError::Invalid("TLV payload too large".into()),
    )?));
    out.extend(payload);
    Ok(out)
}

pub fn iter_tlvs(data: &[u8]) -> AmberResult<Vec<(u64, &[u8])>> {
    let mut items = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let (tag, next) = varint_decode(data, pos)?;
        let (len, next2) = varint_decode(data, next)?;
        let len = usize::try_from(len)
            .map_err(|_| AmberError::Invalid("TLV length out of range".into()))?;
        if next2.checked_add(len).is_none_or(|end| end > data.len()) {
            return Err(AmberError::Invalid("TLV length out of range".into()));
        }
        items.push((tag, &data[next2..next2 + len]));
        pos = next2 + len;
    }
    Ok(items)
}

fn decode_str(data: &[u8]) -> AmberResult<String> {
    std::str::from_utf8(data)
        .map(|s| s.to_owned())
        .map_err(|_| AmberError::Invalid("invalid utf-8".into()))
}

fn parse_time_map(data: &[u8]) -> AmberResult<TlvMap> {
    let (sec, pos) = varint_decode(data, 0)?;
    let (nsec, _) = varint_decode(data, pos)?;
    Ok(map_of([
        ("sec", TlvValue::U64(sec)),
        ("nsec", TlvValue::U64(nsec)),
    ]))
}

fn map_of<const N: usize>(pairs: [(&str, TlvValue); N]) -> TlvMap {
    let mut map = TlvMap::new();
    for (k, v) in pairs {
        map.insert(k.to_string(), v);
    }
    map
}

pub fn get_u64(map: &TlvMap, key: &str) -> Option<u64> {
    match map.get(key) {
        Some(TlvValue::U64(value)) => Some(*value),
        _ => None,
    }
}

fn req_u64(map: &TlvMap, key: &str) -> AmberResult<u64> {
    get_u64(map, key)
        .ok_or_else(|| AmberError::Invalid(format!("missing required integer field: {key}")))
}

pub fn get_bool(map: &TlvMap, key: &str) -> Option<bool> {
    match map.get(key) {
        Some(TlvValue::Bool(value)) => Some(*value),
        _ => None,
    }
}

pub fn get_bytes<'a>(map: &'a TlvMap, key: &str) -> Option<&'a [u8]> {
    match map.get(key) {
        Some(TlvValue::Bytes(value)) => Some(value),
        _ => None,
    }
}

fn require_nonempty_bytes(field: &str, value: &[u8]) -> AmberResult<()> {
    if value.is_empty() {
        return Err(AmberError::Invalid(format!(
            "{field} must not be empty when present"
        )));
    }
    Ok(())
}

pub fn get_string<'a>(map: &'a TlvMap, key: &str) -> Option<&'a str> {
    match map.get(key) {
        Some(TlvValue::String(value)) => Some(value),
        _ => None,
    }
}

fn req_string<'a>(map: &'a TlvMap, key: &str) -> AmberResult<&'a str> {
    get_string(map, key)
        .ok_or_else(|| AmberError::Invalid(format!("missing required string field: {key}")))
}

pub fn get_map<'a>(map: &'a TlvMap, key: &str) -> Option<&'a TlvMap> {
    match map.get(key) {
        Some(TlvValue::Map(value)) => Some(value),
        _ => None,
    }
}

pub fn get_list<'a>(map: &'a TlvMap, key: &str) -> Option<&'a Vec<TlvMap>> {
    match map.get(key) {
        Some(TlvValue::List(value)) => Some(value),
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/tlv.rs"]
mod tests;

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::archiveio::{LogicalArchiveAppender, LogicalArchiveReader};
use crate::codec::Codec;
use crate::constants::{
    CODEC_MDS_PARITY, FLAG_ENCRYPTED, KDF_ARGON2ID_V2, REC_SYNC, RTYPE_ANCHOR, RTYPE_CHUNK,
    RTYPE_ENTRY_BEGIN, VERSION_MAJOR, VERSION_MINOR,
};
use crate::crc32c::crc32c;
use crate::encryption::{EncryptionContext, EncryptionParams, derive_user_secret};
use crate::error::{AmberError, AmberResult};
use crate::globalparity::validate_global_parity_scheme;
use crate::hashutil::{blake3_32, merkle_leaf_from_chunk_tag, merkle_parent};
use crate::records::{RECORD_HEADER_SIZE, parse_chunk_header_ext, read_record_at_bounded};
use crate::superblock::{SUPERBLOCK_SIZE, read_superblock};
use crate::tlv::{
    TlvMap, TlvValue, dumps_index, get_bool, get_bytes, get_u64, iter_tlvs, loads_anchor,
    varint_decode,
};
use crate::trailer::{metadata_checkpoint_valid, write_index_trailer_with_segments_appender};
use crate::writer::CANONICAL_WRITER_INFO;

const DEFAULT_REBUILD_SYMBOL_SIZE: u64 = 65_536;
const MAX_REBUILD_ANCHOR_PAYLOAD_LEN: u64 = 1 << 20;

pub fn rebuild_index(
    path: impl AsRef<Path>,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<usize> {
    let mut decryptor: Option<EncryptionContext> = None;
    let mut entries: Vec<TlvMap> = Vec::new();
    let mut entry_map: BTreeMap<u64, usize> = BTreeMap::new();
    let mut symbols: Vec<TlvMap> = Vec::new();
    let mut mds_parities: Vec<TlvMap> = Vec::new();
    let mut mds_seed_base = Vec::new();
    let mut global_parity_scheme: Option<String> = None;
    let mut anchors_meta_raw: Vec<RawAnchorMeta> = Vec::new();

    let mut f = LogicalArchiveReader::open_path(path.as_ref())?;
    let superblock = read_superblock(&mut f)?;
    if (superblock.flags & FLAG_ENCRYPTED) != 0 {
        let secret = derive_user_secret(password, keyfile)?.ok_or_else(|| {
            AmberError::Invalid(
                "Archive is encrypted; password or keyfile required for index rebuild".into(),
            )
        })?;
        if superblock.kdf_id != KDF_ARGON2ID_V2 {
            return Err(AmberError::Invalid(
                "Unsupported KDF for encrypted archive".into(),
            ));
        }
        decryptor = Some(EncryptionContext::from_params_secret(
            &secret,
            EncryptionParams {
                salt: superblock.kdf_salt,
                time_cost: superblock.argon_time_cost,
                memory_cost_kib: superblock.argon_memory_cost,
                parallelism: superblock.argon_parallelism,
            },
        )?);
    }
    let symbol_size =
        discover_rebuild_symbol_size(path.as_ref(), decryptor.as_ref(), superblock.uuid)?;
    f.seek(SeekFrom::Start(SUPERBLOCK_SIZE as u64))?;
    loop {
        let rec_start = f.stream_position()?;
        let mut fixed = [0u8; RECORD_HEADER_SIZE];
        match f.read_exact(&mut fixed) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err.into()),
        }
        if fixed[..4] != REC_SYNC {
            break;
        }
        let rtype = fixed[4];
        let header_len = u16::from_le_bytes([fixed[6], fixed[7]]) as usize;
        let payload_len = u64::from_le_bytes(fixed[8..16].try_into().unwrap());
        let hdr_crc = u32::from_le_bytes(fixed[16..20].try_into().unwrap());
        let mut header_ext = vec![0u8; header_len];
        f.read_exact(&mut header_ext)?;
        let calc_crc = crc32c(&fixed[..16], 0);
        let calc_crc = crc32c(&header_ext, calc_crc);
        if calc_crc != hdr_crc {
            break;
        }
        let payload_offset = f.stream_position()?;
        let mut payload = vec![
            0u8;
            usize::try_from(payload_len).map_err(|_| AmberError::Invalid(
                "record payload too large".into()
            ))?
        ];
        match f.read_exact(&mut payload) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err.into()),
        }
        let mut header_bytes = fixed.to_vec();
        header_bytes.extend_from_slice(&header_ext);
        let dec_payload = if let Some(decryptor) = decryptor.as_ref() {
            if matches!(rtype, RTYPE_ENTRY_BEGIN | RTYPE_ANCHOR) {
                decryptor.decrypt(&header_bytes, &payload, &rec_start.to_le_bytes())?
            } else {
                payload.clone()
            }
        } else {
            payload.clone()
        };

        match rtype {
            RTYPE_ENTRY_BEGIN => {
                let ent = parse_entry_begin(&dec_payload)?;
                let eid = get_u64(&ent, "entry_id").unwrap_or(0);
                if eid != 0 {
                    entry_map.insert(eid, entries.len());
                    entries.push(ent);
                }
            }
            RTYPE_CHUNK => {
                let (entry_id, chunk_index, ulen, codec_id, _flags, tag32, aux16) =
                    parse_chunk_header_ext(&header_ext)?;
                if entry_id != 0
                    && let Some(index) = entry_map.get(&entry_id).copied()
                {
                    let entry = &mut entries[index];
                    entry
                        .entry("_raw_chunk_count".into())
                        .and_modify(|value| {
                            if let TlvValue::U64(v) = value {
                                *v += 1;
                            }
                        })
                        .or_insert(TlvValue::U64(1));
                    let chunks = match entry.get_mut("chunks") {
                        Some(TlvValue::List(chunks)) => chunks,
                        _ => {
                            entry.insert("chunks".into(), TlvValue::List(Vec::new()));
                            match entry.get_mut("chunks") {
                                Some(TlvValue::List(chunks)) => chunks,
                                _ => unreachable!(),
                            }
                        }
                    };
                    let mut chunk = TlvMap::new();
                    chunk.insert("offset".into(), TlvValue::U64(rec_start));
                    chunk.insert("payload_offset".into(), TlvValue::U64(payload_offset));
                    chunk.insert("payload_len".into(), TlvValue::U64(payload_len));
                    chunk.insert("uncompressed_len".into(), TlvValue::U64(ulen as u64));
                    chunk.insert("chunk_index".into(), TlvValue::U64(chunk_index as u64));
                    chunk.insert("blake3_32".into(), TlvValue::Bytes(tag32.to_vec()));
                    chunks.push(chunk);
                }

                let header_bytes = [fixed.as_slice(), header_ext.as_slice()].concat();
                if codec_id == CODEC_MDS_PARITY {
                    let dec_payload = if let Some(decryptor) = decryptor.as_ref() {
                        decryptor.decrypt(&header_bytes, &payload, &rec_start.to_le_bytes())?
                    } else {
                        payload.clone()
                    };
                    let sym_index = symbols.len() as u64;
                    let parity_tag =
                        blake3_32(&dec_payload[..dec_payload.len().min(symbol_size as usize)]);
                    symbols.push(build_symbol_map(
                        sym_index,
                        payload_offset,
                        rec_start,
                        payload_len,
                        &parity_tag,
                        true,
                        Some(&aux16),
                    ));
                    let mut parity = TlvMap::new();
                    parity.insert("symbol_index".into(), TlvValue::U64(sym_index));
                    parity.insert("seed_id".into(), TlvValue::U64(chunk_index as u64));
                    parity.insert("offset".into(), TlvValue::U64(payload_offset));
                    parity.insert("length".into(), TlvValue::U64(payload_len));
                    parity.insert("tag32".into(), TlvValue::Bytes(parity_tag.to_vec()));
                    parity.insert("seed_base".into(), TlvValue::Bytes(aux16.to_vec()));
                    parity.insert("row_count".into(), TlvValue::U64(0));
                    mds_parities.push(parity);
                } else {
                    let trusted_symbol_tags = match decryptor.as_ref() {
                        Some(decryptor) => decryptor
                            .decrypt(&header_bytes, &payload, &rec_start.to_le_bytes())
                            .ok()
                            .and_then(|plain| {
                                Codec::new(codec_id)
                                    .decompress(&plain, Some(ulen as usize))
                                    .ok()
                                    .map(|raw| {
                                        raw.len() == ulen as usize && blake3_32(&raw) == tag32
                                    })
                            })
                            .unwrap_or(false),
                        None => Codec::new(codec_id)
                            .decompress(&payload, Some(ulen as usize))
                            .ok()
                            .map(|raw| raw.len() == ulen as usize && blake3_32(&raw) == tag32)
                            .unwrap_or(false),
                    };
                    let mut pos = 0usize;
                    while pos < payload.len() {
                        let end = (pos + symbol_size as usize).min(payload.len());
                        let sym_bytes = &payload[pos..end];
                        let sym_index = symbols.len() as u64;
                        let tag = if trusted_symbol_tags {
                            blake3_32(sym_bytes)
                        } else {
                            [0u8; 32]
                        };
                        symbols.push(build_symbol_map(
                            sym_index,
                            payload_offset + pos as u64,
                            rec_start,
                            sym_bytes.len() as u64,
                            &tag,
                            false,
                            None,
                        ));
                        pos = end;
                    }
                }
            }
            RTYPE_ANCHOR => {
                if let Ok(anchor) = loads_anchor(&dec_payload, 1024) {
                    if let Some(anchor) =
                        parse_raw_anchor_meta(&anchor, rec_start, symbol_size, superblock.uuid)
                    {
                        anchors_meta_raw.push(anchor);
                    }
                }
            }
            _ => {}
        }
    }

    let symbol_by_offset = symbols
        .iter()
        .filter_map(|symbol| get_u64(symbol, "offset").map(|offset| (offset, symbol.clone())))
        .collect::<BTreeMap<_, _>>();
    let mut validated_anchors = Vec::new();
    for anchor in anchors_meta_raw {
        if anchor.version != 1 || anchor.symbol_size != symbol_size {
            continue;
        }
        let mut valid = true;
        for sample in &anchor.symbols {
            let Some(base) = symbol_by_offset.get(&sample.offset) else {
                valid = false;
                break;
            };
            if get_u64(base, "length").unwrap_or(u64::MAX) != sample.length
                || get_bool(base, "is_parity").unwrap_or(false) != sample.is_parity
            {
                valid = false;
                break;
            }
            if let Some(sample_ro) = sample.record_offset
                && get_u64(base, "record_offset").unwrap_or(u64::MAX) != sample_ro
            {
                valid = false;
                break;
            }
            if decryptor.is_none() {
                let base_tag = get_bytes(base, "tag32").unwrap_or(&[]);
                if !sample.tag32.is_empty()
                    && (sample.tag32.len() != 32
                        || (!base_tag.is_empty() && sample.tag32 != base_tag))
                {
                    valid = false;
                    break;
                }
            }
        }
        if !valid {
            continue;
        }
        let count = anchor.symbols.len() as u64;
        let first_symbol = anchor.symbols.first().map(|s| s.symbol_index).unwrap_or(0);
        let last_symbol = anchor.symbols.last().map(|s| s.symbol_index).unwrap_or(0);
        validated_anchors.push(ValidatedAnchorMeta {
            offset: anchor.offset,
            symbol_count: count,
            first_symbol,
            last_symbol,
            seed_base: anchor.seed_base,
            scheme: anchor.scheme,
        });
    }

    let mut vf = LogicalArchiveReader::open_path(path.as_ref())?;
    for entry in &mut entries {
        if get_u64(entry, "kind").unwrap_or(0) != 0 {
            entry.remove("_raw_chunk_count");
            continue;
        }
        let old_chunks = match entry.remove("chunks") {
            Some(TlvValue::List(chunks)) => chunks,
            _ => Vec::new(),
        };
        let mut good = Vec::new();
        for ch in old_chunks {
            let Some(offset) = get_u64(&ch, "offset") else {
                continue;
            };
            let Some(payload_len) = get_u64(&ch, "payload_len") else {
                continue;
            };
            let Ok(record) = read_record_at_bounded(&mut vf, offset, None, payload_len) else {
                continue;
            };
            if record.rtype != RTYPE_CHUNK {
                continue;
            }
            let Ok((eid, _idx, _ulen, _codec, _flags, _tag, _aux)) =
                parse_chunk_header_ext(&record.header_ext)
            else {
                continue;
            };
            if eid != get_u64(entry, "entry_id").unwrap_or(0) {
                continue;
            }
            good.push(ch);
        }
        good.sort_by_key(|chunk| get_u64(chunk, "chunk_index").unwrap_or(0));
        entry.insert("chunks".into(), TlvValue::List(good));
    }
    let seed_candidates = validated_anchors
        .iter()
        .filter(|anchor| !anchor.seed_base.is_empty())
        .map(|anchor| anchor.seed_base.clone())
        .collect::<Vec<_>>();
    let canonical_seed_base = if !seed_candidates.is_empty() {
        most_common_non_empty_bytes(&seed_candidates)
    } else {
        let parity_seed_candidates = mds_parities
            .iter()
            .filter_map(|item| get_bytes(item, "seed_base").map(|bytes| bytes.to_vec()))
            .collect::<Vec<_>>();
        most_common_non_empty_bytes(&parity_seed_candidates)
    };
    let mut anchors = Vec::new();
    for anchor in &validated_anchors {
        if !canonical_seed_base.is_empty()
            && !anchor.seed_base.is_empty()
            && anchor.seed_base != canonical_seed_base
        {
            continue;
        }
        let mut item = TlvMap::new();
        item.insert("offset".into(), TlvValue::U64(anchor.offset));
        item.insert("symbol_count".into(), TlvValue::U64(anchor.symbol_count));
        item.insert("first_symbol".into(), TlvValue::U64(anchor.first_symbol));
        item.insert("last_symbol".into(), TlvValue::U64(anchor.last_symbol));
        anchors.push(item);
    }
    if !canonical_seed_base.is_empty() {
        mds_seed_base = canonical_seed_base.clone();
    }
    let scheme_candidates = validated_anchors
        .iter()
        .filter_map(|anchor| anchor.scheme.clone())
        .collect::<Vec<_>>();
    if !mds_parities.is_empty() && !scheme_candidates.is_empty() {
        global_parity_scheme = Some(
            validate_global_parity_scheme(&most_common_non_empty_string(&scheme_candidates))
                .map_err(AmberError::Invalid)?
                .to_owned(),
        );
    } else if !mds_parities.is_empty() {
        global_parity_scheme = Some(
            validate_global_parity_scheme("mds")
                .map_err(AmberError::Invalid)?
                .to_owned(),
        );
    }

    let mut problematic = Vec::new();
    for entry in &mut entries {
        if get_u64(entry, "kind").unwrap_or(0) != 0 {
            entry.remove("_raw_chunk_count");
            continue;
        }
        let raw_count = get_u64(entry, "_raw_chunk_count").unwrap_or(0);
        entry.remove("_raw_chunk_count");
        let chunk_count = match entry.get("chunks") {
            Some(TlvValue::List(chunks)) => chunks.len() as u64,
            _ => 0,
        };
        let size = get_u64(entry, "size").unwrap_or(0);
        if (raw_count == 0 && size > 0) || (raw_count > 0 && chunk_count == 0) {
            problematic.push(
                entry
                    .get("path")
                    .and_then(|v| match v {
                        TlvValue::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap_or_else(|| {
                        format!("entry#{}", get_u64(entry, "entry_id").unwrap_or(0))
                    }),
            );
        }
    }
    if !problematic.is_empty() {
        return Err(AmberError::Invalid(format!(
            "Index rebuild aborted: missing chunk metadata for {}",
            problematic.join(", ")
        )));
    }

    let usable_global_parities = if !mds_seed_base.is_empty() && global_parity_scheme.is_some() {
        let scanned_row_count = mds_parities
            .iter()
            .filter(|item| get_bytes(item, "seed_base").unwrap_or(&[]) == mds_seed_base.as_slice())
            .count() as u64;
        for item in &mut mds_parities {
            if get_u64(item, "row_count").unwrap_or(0) == 0
                && get_bytes(item, "seed_base").unwrap_or(&[]) == mds_seed_base.as_slice()
            {
                item.insert("row_count".into(), TlvValue::U64(scanned_row_count));
            }
        }
        mds_parities
            .iter()
            .filter(|item| get_bytes(item, "seed_base").unwrap_or(&[]) == mds_seed_base.as_slice())
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mds_info = if !usable_global_parities.is_empty() {
        let data_symbol_count = symbols
            .iter()
            .filter(|s| !get_bool(s, "is_parity").unwrap_or(false))
            .count();
        let mut mds = TlvMap::new();
        mds.insert(
            "scheme".into(),
            TlvValue::String(
                global_parity_scheme
                    .clone()
                    .unwrap_or_else(|| "mds".into()),
            ),
        );
        mds.insert("seed_base".into(), TlvValue::Bytes(mds_seed_base.clone()));
        mds.insert(
            "epsilon_ppm".into(),
            TlvValue::U64(
                (usable_global_parities.len() * 1_000_000 / data_symbol_count.max(1)) as u64,
            ),
        );
        mds.insert(
            "parity".into(),
            TlvValue::List(usable_global_parities.clone()),
        );
        Some(mds)
    } else {
        None
    };
    let merkle_root = compute_merkle_from_entries(&entries);
    let archive_uuid = superblock.uuid;

    let mut outf = LogicalArchiveAppender::open_path(path.as_ref())?;
    write_index_trailer_with_segments_appender(
        &mut outf,
        if (superblock.flags & FLAG_ENCRYPTED) != 0 {
            decryptor.as_ref()
        } else {
            None
        },
        archive_uuid,
        merkle_root,
        |segments_meta| {
            let mut idx_map = TlvMap::new();
            idx_map.insert(
                "version".into(),
                TlvValue::Map(BTreeMap::from([
                    ("major".into(), TlvValue::U64(VERSION_MAJOR as u64)),
                    ("minor".into(), TlvValue::U64(VERSION_MINOR as u64)),
                ])),
            );
            idx_map.insert(
                "archive_uuid".into(),
                TlvValue::Bytes(archive_uuid.to_vec()),
            );
            idx_map.insert(
                "writer_info".into(),
                TlvValue::String(CANONICAL_WRITER_INFO.into()),
            );
            idx_map.insert(
                "default_chunk_size".into(),
                TlvValue::U64(superblock.default_chunk_size as u64),
            );
            idx_map.insert(
                "default_codec".into(),
                TlvValue::U64(superblock.default_codec as u64),
            );
            idx_map.insert("entries".into(), TlvValue::List(entries.clone()));
            idx_map.insert(
                "ecc_groups".into(),
                TlvValue::List(vec![{
                    let mut group = TlvMap::new();
                    group.insert("group_id".into(), TlvValue::U64(1));
                    group.insert("symbol_size".into(), TlvValue::U64(symbol_size));
                    if let Some(mds) = &mds_info {
                        group.insert("mds".into(), TlvValue::Map(mds.clone()));
                    }
                    group.insert("symbols".into(), TlvValue::List(symbols.clone()));
                    group
                }]),
            );
            idx_map.insert("anchors".into(), TlvValue::List(anchors.clone()));
            idx_map.insert("segments".into(), TlvValue::List(segments_meta.to_vec()));
            dumps_index(&idx_map)
        },
    )?;
    Ok(usable_global_parities.len())
}

fn discover_rebuild_symbol_size(
    path: &Path,
    decryptor: Option<&EncryptionContext>,
    archive_uuid: [u8; 16],
) -> AmberResult<u64> {
    let mut file = LogicalArchiveReader::open_path(path)?;
    file.seek(SeekFrom::Start(SUPERBLOCK_SIZE as u64))?;
    let mut anchor_sizes = Vec::new();
    let mut parity_sizes = Vec::new();
    loop {
        let rec_start = file.stream_position()?;
        let Some((fixed, header_ext, payload_len)) = read_rebuild_record_header(&mut file)? else {
            break;
        };
        let rtype = fixed[4];
        let mut header_bytes = fixed.to_vec();
        header_bytes.extend_from_slice(&header_ext);
        match rtype {
            RTYPE_ANCHOR => {
                if payload_len > MAX_REBUILD_ANCHOR_PAYLOAD_LEN {
                    skip_rebuild_payload(&mut file, payload_len)?;
                    continue;
                }
                let payload = read_rebuild_payload(&mut file, payload_len)?;
                let anchor_payload = if let Some(decryptor) = decryptor {
                    match decryptor.decrypt(&header_bytes, &payload, &rec_start.to_le_bytes()) {
                        Ok(payload) => payload,
                        Err(_) => continue,
                    }
                } else {
                    payload
                };
                if let Ok(anchor) = loads_anchor(&anchor_payload, 1024)
                    && metadata_checkpoint_valid(&anchor, archive_uuid)
                    && let Some(symbol_size) = get_u64(&anchor, "symbol_size")
                {
                    anchor_sizes.push(symbol_size);
                }
            }
            RTYPE_CHUNK => {
                let Ok((_entry_id, _chunk_index, _ulen, codec_id, _flags, _tag32, _aux16)) =
                    parse_chunk_header_ext(&header_ext)
                else {
                    skip_rebuild_payload(&mut file, payload_len)?;
                    continue;
                };
                if codec_id != CODEC_MDS_PARITY {
                    skip_rebuild_payload(&mut file, payload_len)?;
                    continue;
                }
                if let Some(decryptor) = decryptor {
                    let payload = read_rebuild_payload(&mut file, payload_len)?;
                    if let Ok(plain) =
                        decryptor.decrypt(&header_bytes, &payload, &rec_start.to_le_bytes())
                    {
                        parity_sizes.push(plain.len() as u64);
                    }
                } else {
                    parity_sizes.push(payload_len);
                    skip_rebuild_payload(&mut file, payload_len)?;
                }
            }
            _ => {
                skip_rebuild_payload(&mut file, payload_len)?;
            }
        }
    }

    if !anchor_sizes.is_empty() {
        return Ok(most_common_u64(&anchor_sizes));
    }
    if !parity_sizes.is_empty() {
        return Ok(most_common_u64(&parity_sizes));
    }
    Ok(DEFAULT_REBUILD_SYMBOL_SIZE)
}

fn read_rebuild_record_header(
    file: &mut LogicalArchiveReader,
) -> AmberResult<Option<([u8; RECORD_HEADER_SIZE], Vec<u8>, u64)>> {
    let mut fixed = [0u8; RECORD_HEADER_SIZE];
    match file.read_exact(&mut fixed) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    if fixed[..4] != REC_SYNC {
        return Ok(None);
    }
    let header_len = u16::from_le_bytes([fixed[6], fixed[7]]) as usize;
    let payload_len = u64::from_le_bytes(fixed[8..16].try_into().unwrap());
    let hdr_crc = u32::from_le_bytes(fixed[16..20].try_into().unwrap());
    let mut header_ext = vec![0u8; header_len];
    file.read_exact(&mut header_ext)?;
    let calc_crc = crc32c(&fixed[..16], 0);
    let calc_crc = crc32c(&header_ext, calc_crc);
    if calc_crc != hdr_crc {
        return Ok(None);
    }
    Ok(Some((fixed, header_ext, payload_len)))
}

fn read_rebuild_payload(
    file: &mut LogicalArchiveReader,
    payload_len: u64,
) -> AmberResult<Vec<u8>> {
    let mut payload = vec![
        0u8;
        usize::try_from(payload_len)
            .map_err(|_| AmberError::Invalid("record payload too large".into()))?
    ];
    match file.read_exact(&mut payload) {
        Ok(()) => Ok(payload),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(AmberError::Invalid("truncated record payload".into()))
        }
        Err(err) => Err(err.into()),
    }
}

fn skip_rebuild_payload(file: &mut LogicalArchiveReader, payload_len: u64) -> AmberResult<()> {
    file.seek(SeekFrom::Current(i64::try_from(payload_len).map_err(
        |_| AmberError::Invalid("record payload too large to skip".into()),
    )?))?;
    Ok(())
}

#[derive(Clone, Debug)]
struct RawAnchorSymbol {
    symbol_index: u64,
    offset: u64,
    length: u64,
    tag32: Vec<u8>,
    is_parity: bool,
    record_offset: Option<u64>,
}

#[derive(Clone, Debug)]
struct RawAnchorMeta {
    offset: u64,
    symbols: Vec<RawAnchorSymbol>,
    seed_base: Vec<u8>,
    scheme: Option<String>,
    symbol_size: u64,
    version: u64,
}

#[derive(Clone, Debug)]
struct ValidatedAnchorMeta {
    offset: u64,
    symbol_count: u64,
    first_symbol: u64,
    last_symbol: u64,
    seed_base: Vec<u8>,
    scheme: Option<String>,
}

fn parse_entry_begin(payload: &[u8]) -> AmberResult<TlvMap> {
    let mut ent = TlvMap::new();
    ent.insert("chunks".into(), TlvValue::List(Vec::new()));
    for (tag, pl) in iter_tlvs(payload)? {
        match tag {
            1 => {
                ent.insert("entry_id".into(), TlvValue::U64(varint_decode(pl, 0)?.0));
            }
            2 => {
                ent.insert("kind".into(), TlvValue::U64(varint_decode(pl, 0)?.0));
            }
            3 => {
                ent.insert("path".into(), TlvValue::String(decode_str(pl)?));
            }
            4 => {
                ent.insert("mode".into(), TlvValue::U64(varint_decode(pl, 0)?.0));
            }
            5 => {
                let (sec, pos) = varint_decode(pl, 0)?;
                let (nsec, _) = varint_decode(pl, pos)?;
                ent.insert(
                    "mtime".into(),
                    TlvValue::Map(BTreeMap::from([
                        ("sec".into(), TlvValue::U64(sec)),
                        ("nsec".into(), TlvValue::U64(nsec)),
                    ])),
                );
            }
            6 => {
                let (sec, pos) = varint_decode(pl, 0)?;
                let (nsec, _) = varint_decode(pl, pos)?;
                ent.insert(
                    "atime".into(),
                    TlvValue::Map(BTreeMap::from([
                        ("sec".into(), TlvValue::U64(sec)),
                        ("nsec".into(), TlvValue::U64(nsec)),
                    ])),
                );
            }
            7 => {
                ent.insert("size".into(), TlvValue::U64(varint_decode(pl, 0)?.0));
            }
            8 => {
                ent.insert("file_codec".into(), TlvValue::U64(varint_decode(pl, 0)?.0));
            }
            9 => {
                ent.insert("chunk_size".into(), TlvValue::U64(varint_decode(pl, 0)?.0));
            }
            10 => {
                ent.insert("symlink_target".into(), TlvValue::String(decode_str(pl)?));
            }
            _ => {}
        }
    }
    Ok(ent)
}

fn parse_raw_anchor_meta(
    anchor: &TlvMap,
    offset: u64,
    default_symbol_size: u64,
    archive_uuid: [u8; 16],
) -> Option<RawAnchorMeta> {
    if !metadata_checkpoint_valid(anchor, archive_uuid) {
        return None;
    }
    let declared_symbol_size = get_u64(anchor, "symbol_size").unwrap_or(default_symbol_size);
    let seed_base = get_bytes(anchor, "seed_base").unwrap_or(&[]).to_vec();
    let version = get_u64(anchor, "version").unwrap_or(1);
    let mut syms = Vec::new();
    for s in anchor
        .get("symbols")
        .and_then(|v| match v {
            TlvValue::List(v) => Some(v),
            _ => None,
        })
        .cloned()
        .unwrap_or_default()
    {
        let symbol_index = get_u64(&s, "symbol_index").unwrap_or(u64::MAX);
        let offset_val = get_u64(&s, "offset").unwrap_or(0);
        let length_val = get_u64(&s, "length").unwrap_or(0);
        syms.push(RawAnchorSymbol {
            symbol_index,
            offset: offset_val,
            length: length_val,
            tag32: get_bytes(&s, "tag32").unwrap_or(&[]).to_vec(),
            is_parity: get_bool(&s, "is_parity").unwrap_or(false),
            record_offset: get_u64(&s, "record_offset"),
        });
    }
    Some(RawAnchorMeta {
        offset,
        symbols: syms,
        seed_base,
        scheme: anchor.get("scheme").and_then(|v| match v {
            TlvValue::String(s) => Some(s.clone()),
            _ => None,
        }),
        symbol_size: declared_symbol_size,
        version,
    })
}

fn build_symbol_map(
    sym_index: u64,
    offset: u64,
    record_offset: u64,
    length: u64,
    tag32: &[u8; 32],
    is_parity: bool,
    seed_base: Option<&[u8; 16]>,
) -> TlvMap {
    let mut symbol = TlvMap::new();
    symbol.insert("symbol_index".into(), TlvValue::U64(sym_index));
    symbol.insert("offset".into(), TlvValue::U64(offset));
    symbol.insert("record_offset".into(), TlvValue::U64(record_offset));
    symbol.insert("length".into(), TlvValue::U64(length));
    symbol.insert("tag32".into(), TlvValue::Bytes(tag32.to_vec()));
    symbol.insert("stripe_index".into(), TlvValue::U64(u64::MAX));
    symbol.insert("is_parity".into(), TlvValue::Bool(is_parity));
    if let Some(seed_base) = seed_base {
        symbol.insert("seed_base".into(), TlvValue::Bytes(seed_base.to_vec()));
    }
    symbol
}

fn compute_merkle_from_entries(entries: &[TlvMap]) -> [u8; 32] {
    let mut leaves = Vec::new();
    for entry in entries {
        if get_u64(entry, "kind").unwrap_or(0) != 0 {
            continue;
        }
        if let Some(TlvValue::List(chunks)) = entry.get("chunks") {
            for chunk in chunks {
                if let Some(tag) = get_bytes(chunk, "blake3_32")
                    && tag.len() == 32
                {
                    let mut tag32 = [0u8; 32];
                    tag32.copy_from_slice(tag);
                    leaves.push(merkle_leaf_from_chunk_tag(&tag32));
                }
            }
        }
    }
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut idx = 0usize;
        while idx < level.len() {
            let left = level[idx];
            if idx + 1 >= level.len() {
                next.push(left);
                break;
            }
            next.push(merkle_parent(&left, &level[idx + 1]));
            idx += 2;
        }
        level = next;
    }
    level[0]
}

fn most_common_non_empty_bytes(values: &[Vec<u8>]) -> Vec<u8> {
    if values.is_empty() {
        return Vec::new();
    }
    let mut counts = BTreeMap::<Vec<u8>, usize>::new();
    for value in values {
        *counts.entry(value.clone()).or_insert(0) += 1;
    }
    counts
        .iter()
        .filter(|(value, _)| !value.is_empty())
        .max_by_key(|(_, count)| **count)
        .or_else(|| counts.iter().max_by_key(|(_, count)| **count))
        .map(|(value, _)| value.clone())
        .unwrap_or_default()
}

fn most_common_u64(values: &[u64]) -> u64 {
    let mut counts = BTreeMap::<u64, usize>::new();
    for value in values {
        *counts.entry(*value).or_insert(0) += 1;
    }
    let mut best = DEFAULT_REBUILD_SYMBOL_SIZE;
    let mut best_count = 0usize;
    for (value, count) in counts {
        if count > best_count {
            best = value;
            best_count = count;
        }
    }
    best
}

fn most_common_non_empty_string(values: &[String]) -> String {
    let mut counts = BTreeMap::<String, usize>::new();
    for value in values {
        *counts.entry(value.clone()).or_insert(0) += 1;
    }
    counts
        .iter()
        .filter(|(value, _)| !value.is_empty())
        .max_by_key(|(_, count)| **count)
        .or_else(|| counts.iter().max_by_key(|(_, count)| **count))
        .map(|(value, _)| value.clone())
        .unwrap_or_default()
}

fn decode_str(data: &[u8]) -> AmberResult<String> {
    std::str::from_utf8(data)
        .map(|s| s.to_owned())
        .map_err(|_| AmberError::Invalid("invalid utf-8".into()))
}

#[cfg(test)]
#[path = "tests/recover.rs"]
mod tests;

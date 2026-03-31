use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::fill;

use crate::amcfcompute::iter_parity_payloads;
use crate::archiveio::LogicalArchiveWriter;
use crate::chunkemit::{ChunkEmitContext, emit_file_chunks};
use crate::constants::{
    CODEC_AMCF_PARITY, CODEC_NONE, DEFAULT_CHUNK_SIZE, DEFAULT_CODEC_ID,
    FLAG_CHUNK_COMPRESS_DEFAULT, FLAG_ECC_PRESENT, FLAG_ENCRYPTED, KDF_ARGON2ID_V2,
    RFLAG_CHUNK_TAG_PRESENT, RFLAG_PARITY_RECORD, RTYPE_CHUNK, RTYPE_ENTRY_BEGIN, RTYPE_ENTRY_END,
    VERSION_MAJOR, VERSION_MINOR, new_uuid_bytes,
};
use crate::encryption::{EncryptionContext, derive_user_secret};
use crate::entryutil::{EntryBeginPayload, build_entry_begin_payload};
use crate::error::{AmberError, AmberResult};
use crate::globalparity::{
    GLOBAL_PARITY_SCHEME_AMCF, GenericGlobalParitySampler, MIN_TOTAL_PARITY_ROWS_FLOOR,
    canonical_global_parity_rows, require_canonical_global_parity_scheme,
};
use crate::hashutil::{merkle_leaf_from_chunk_tag, merkle_parent};
use crate::pathutil::{validate_archive_path, validate_symlink_target};
use crate::reader::{AmcfParityInfo, ChunkDesc, SymbolInfo};
use crate::records::{build_chunk_header_ext, write_record};
use crate::superblock::{SuperblockEncryptionParams, pack_superblock};
use crate::tlv::{TlvMap, TlvValue, dumps_index};
use crate::trailer::{
    build_anchor_payload, write_anchor_record, write_index_trailer_with_segments,
};

pub const CANONICAL_WRITER_INFO: &str = "amber";

#[derive(Debug)]
pub struct ArchiveWriter {
    pub out_path: PathBuf,
    pub part_size: Option<u64>,
    pub file: Option<LogicalArchiveWriter>,
    pub flags: u32,
    pub encryptor: Option<EncryptionContext>,
    pub default_chunk_size: u32,
    pub default_codec: u16,
    pub archive_uuid: [u8; 16],
    pub entries: Vec<WriterEntry>,
    next_entry_id: u64,
    pub symbols: Vec<SymbolInfo>,
    pub symbol_size: u64,
    pub symbol_data: BTreeMap<usize, Vec<u8>>,
    pub amcf_seed_base: [u8; 16],
    pub global_parity_scheme: &'static str,
    pub min_total_parity_rows: Option<usize>,
    pub amcf_epsilon_ppm: Option<usize>,
    pub amcf_parities: Vec<AmcfParityInfo>,
    pub anchors: Vec<TlvMap>,
    pub anchor_interval_bytes: u64,
    bytes_since_anchor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriterEntry {
    pub entry_id: u64,
    pub kind: u64,
    pub path: String,
    pub size: u64,
    pub mode: Option<u64>,
    pub mtime_sec: Option<u64>,
    pub mtime_nsec: Option<u64>,
    pub atime_sec: Option<u64>,
    pub atime_nsec: Option<u64>,
    pub file_codec: Option<u64>,
    pub chunk_size: Option<u64>,
    pub chunks: Vec<ChunkDesc>,
    pub file_hash32: Option<[u8; 32]>,
    pub symlink_target: Option<String>,
}

impl ArchiveWriter {
    pub fn new(
        out_path: impl AsRef<Path>,
        default_chunk_size: Option<u32>,
        default_codec: Option<u16>,
        password: Option<&str>,
        keyfile: Option<&Path>,
        part_size: Option<u64>,
        amcf_epsilon_ppm: Option<usize>,
        min_total_parity_rows: Option<usize>,
        global_parity_scheme: Option<&str>,
        anchor_interval_bytes: Option<u64>,
    ) -> AmberResult<Self> {
        let default_codec = default_codec.unwrap_or(DEFAULT_CODEC_ID);
        let mut flags = 0u32;
        if default_codec != CODEC_NONE {
            flags |= FLAG_CHUNK_COMPRESS_DEFAULT;
        }
        let secret = derive_user_secret(password, keyfile)?;
        let encryptor = match secret {
            Some(secret) => {
                flags |= FLAG_ENCRYPTED;
                Some(EncryptionContext::create_from_secret(&secret)?)
            }
            None => None,
        };
        flags |= FLAG_ECC_PRESENT;
        Ok(Self {
            out_path: out_path.as_ref().to_path_buf(),
            part_size,
            file: None,
            flags,
            encryptor,
            default_chunk_size: default_chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE),
            default_codec,
            archive_uuid: new_uuid_bytes(),
            entries: Vec::new(),
            next_entry_id: 1,
            symbols: Vec::new(),
            symbol_size: 65_536,
            symbol_data: BTreeMap::new(),
            amcf_seed_base: random_array_16()?,
            global_parity_scheme: require_canonical_global_parity_scheme(
                global_parity_scheme.unwrap_or(GLOBAL_PARITY_SCHEME_AMCF),
            )
            .map_err(AmberError::Invalid)?,
            min_total_parity_rows: min_total_parity_rows.or(Some(MIN_TOTAL_PARITY_ROWS_FLOOR)),
            amcf_epsilon_ppm,
            amcf_parities: Vec::new(),
            anchors: Vec::new(),
            anchor_interval_bytes: anchor_interval_bytes.unwrap_or(64 * 1024 * 1024),
            bytes_since_anchor: 0,
        })
    }

    pub fn open(&mut self) -> AmberResult<()> {
        if self.file.is_some() {
            return Ok(());
        }
        let mut writer = LogicalArchiveWriter::new(&self.out_path, self.part_size)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let enc_params = self.encryptor.as_ref().map(|enc| {
            let params = enc.export_params();
            SuperblockEncryptionParams {
                kdf_id: KDF_ARGON2ID_V2,
                salt: params.salt,
                argon_mem: params.memory_cost_kib,
                argon_time: params.time_cost,
                argon_lanes: params.parallelism,
            }
        });
        let sb = pack_superblock(
            self.flags,
            self.archive_uuid,
            now.as_secs(),
            0,
            self.default_chunk_size,
            self.default_codec as u32,
            self.part_size,
            enc_params.as_ref(),
        );
        writer.write_all(&sb)?;
        writer.set_segment_header_bytes(&sb)?;
        self.file = Some(writer);
        Ok(())
    }

    pub fn close(&mut self) {
        self.file = None;
    }

    pub fn add_dir(
        &mut self,
        arc_path: &str,
        mode: Option<u64>,
        mtime_sec: Option<u64>,
        mtime_nsec: Option<u64>,
        atime_sec: Option<u64>,
        atime_nsec: Option<u64>,
    ) -> AmberResult<()> {
        let entry = WriterEntry {
            entry_id: self.alloc_id(),
            kind: 1,
            path: validate_archive_path(arc_path)?,
            size: 0,
            mode,
            mtime_sec,
            mtime_nsec,
            atime_sec,
            atime_nsec,
            file_codec: None,
            chunk_size: None,
            chunks: Vec::new(),
            file_hash32: None,
            symlink_target: None,
        };
        self.write_entry_begin(&entry)?;
        self.write_entry_end(entry.entry_id, 0)?;
        self.entries.push(entry);
        Ok(())
    }

    pub fn add_symlink(&mut self, arc_path: &str, target: &str) -> AmberResult<()> {
        let entry = WriterEntry {
            entry_id: self.alloc_id(),
            kind: 2,
            path: validate_archive_path(arc_path)?,
            size: 0,
            mode: None,
            mtime_sec: None,
            mtime_nsec: None,
            atime_sec: None,
            atime_nsec: None,
            file_codec: None,
            chunk_size: None,
            chunks: Vec::new(),
            file_hash32: None,
            symlink_target: Some(validate_symlink_target(target)?),
        };
        self.write_entry_begin(&entry)?;
        self.write_entry_end(entry.entry_id, 0)?;
        self.entries.push(entry);
        Ok(())
    }

    pub fn add_file(
        &mut self,
        arc_path: &str,
        fs_path: impl AsRef<Path>,
        codec_id: Option<u16>,
        chunk_size: Option<u32>,
        mode: Option<u64>,
    ) -> AmberResult<()> {
        let st = std::fs::metadata(fs_path.as_ref())?;
        let entry_mode = mode.or(Some(st.permissions().mode() as u64 & 0o7777));
        let (mtime_sec, mtime_nsec, atime_sec, atime_nsec) = file_times_from_metadata(&st);
        self.add_file_with_metadata(
            arc_path,
            fs_path,
            codec_id,
            chunk_size,
            entry_mode,
            mtime_sec,
            mtime_nsec,
            atime_sec,
            atime_nsec,
        )
    }

    pub fn add_file_with_metadata(
        &mut self,
        arc_path: &str,
        fs_path: impl AsRef<Path>,
        codec_id: Option<u16>,
        chunk_size: Option<u32>,
        mode: Option<u64>,
        mtime_sec: Option<u64>,
        mtime_nsec: Option<u64>,
        atime_sec: Option<u64>,
        atime_nsec: Option<u64>,
    ) -> AmberResult<()> {
        let arc_path = validate_archive_path(arc_path)?;
        let chunk_size = chunk_size
            .filter(|chunk_size| *chunk_size != 0)
            .unwrap_or(self.default_chunk_size);
        let codec_id = codec_id.unwrap_or(self.default_codec);
        let st = std::fs::metadata(fs_path.as_ref())?;
        let entry_id = self.alloc_id();
        let mut entry = WriterEntry {
            entry_id,
            kind: 0,
            path: arc_path,
            size: st.len(),
            mode,
            mtime_sec,
            mtime_nsec,
            atime_sec,
            atime_nsec,
            file_codec: Some(codec_id as u64),
            chunk_size: Some(chunk_size as u64),
            chunks: Vec::new(),
            file_hash32: None,
            symlink_target: None,
        };
        self.write_entry_begin(&entry)?;

        let encryptor = self.encryptor.as_ref();
        let prior_entries = self.entries.clone();
        let symbols = &mut self.symbols;
        let symbol_data = std::mem::take(&mut self.symbol_data);
        let anchor_interval_bytes = self.anchor_interval_bytes;
        let bytes_since_anchor = &mut self.bytes_since_anchor;
        let amcf_seed_base = self.amcf_seed_base;
        let global_parity_scheme = self.global_parity_scheme;
        let anchors = &mut self.anchors;
        let file_writer = self
            .file
            .as_mut()
            .ok_or_else(|| AmberError::Invalid("Archive not open".into()))?;
        let mut ctx = ChunkEmitContext {
            fh: file_writer,
            encryptor,
            symbol_size: self.symbol_size as usize,
            next_symbol_index: symbols.len(),
            symbol_bytes: symbol_data,
            symbol_append: Box::new(
                move |fh, sym_index, record_offset, payload_offset, length, tag32, _data_bytes| {
                    symbols.push(SymbolInfo {
                        symbol_index: sym_index as u64,
                        offset: payload_offset,
                        record_offset,
                        length: length as u64,
                        tag32,
                        stripe_index: -1,
                        is_parity: false,
                        seed_base: None,
                    });
                    if anchor_interval_bytes != 0 {
                        *bytes_since_anchor += length as u64;
                        if *bytes_since_anchor >= anchor_interval_bytes {
                            let merkle_root =
                                compute_merkle_root_for_entries(&prior_entries, symbols);
                            let symbol_maps = symbol_tlv_maps(symbols);
                            let anchor_payload = build_anchor_payload(
                                &symbol_maps,
                                65_536,
                                merkle_root,
                                Some(&amcf_seed_base),
                                Some(global_parity_scheme),
                            );
                            let off = write_anchor_record(fh, &anchor_payload, encryptor)?;
                            anchors.push(anchor_meta_map(symbols, off));
                            *bytes_since_anchor = 0;
                        }
                    }
                    Ok(())
                },
            ),
        };
        let (chunks, file_hash32) = emit_file_chunks(
            &mut ctx,
            entry.entry_id,
            fs_path.as_ref(),
            codec_id,
            chunk_size as usize,
        )?;
        self.symbol_data = std::mem::take(&mut ctx.symbol_bytes);
        drop(ctx);
        entry.chunks = chunks
            .iter()
            .map(|chunk| ChunkDesc {
                offset: chunk.offset,
                payload_offset: chunk.payload_offset,
                payload_len: chunk.payload_len,
                uncompressed_len: chunk.uncompressed_len,
                chunk_index: chunk.chunk_index,
                tag32: chunk.blake3_32,
            })
            .collect();
        entry.file_hash32 = Some(file_hash32);
        self.write_entry_end(entry.entry_id, entry.chunks.len() as u32)?;
        self.entries.push(entry);
        Ok(())
    }

    pub fn finalize(&mut self) -> AmberResult<()> {
        self.generate_global_parity()?;
        let merkle_root = self.compute_merkle_root();
        let symbol_maps = symbol_tlv_maps(&self.symbols);
        let payload = build_anchor_payload(
            &symbol_maps,
            self.symbol_size,
            merkle_root,
            Some(&self.amcf_seed_base),
            Some(self.global_parity_scheme),
        );
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| AmberError::Invalid("Archive not open".into()))?;
        let off = write_anchor_record(file, &payload, self.encryptor.as_ref())?;
        self.anchors.push(anchor_meta_map(&self.symbols, off));
        let archive_uuid = self.archive_uuid;
        let encryptor = self.encryptor.as_ref();
        let merkle_root_copy = merkle_root;
        let default_chunk_size = self.default_chunk_size;
        let default_codec = self.default_codec;
        let entries = self.entries.clone();
        let symbols = self.symbols.clone();
        let amcf_parities = self.amcf_parities.clone();
        let anchors = self.anchors.clone();
        let scheme = self.global_parity_scheme;
        let seed_base = self.amcf_seed_base;
        write_index_trailer_with_segments(
            file,
            encryptor,
            archive_uuid,
            merkle_root_copy,
            |segments_meta| {
                build_index_payload(
                    archive_uuid,
                    default_chunk_size,
                    default_codec,
                    &entries,
                    &symbols,
                    &amcf_parities,
                    &anchors,
                    segments_meta,
                    scheme,
                    seed_base,
                    self.symbol_size,
                )
            },
        )?;
        Ok(())
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_entry_id;
        self.next_entry_id += 1;
        id
    }

    fn write_entry_begin(&mut self, entry: &WriterEntry) -> AmberResult<()> {
        let payload = build_entry_begin_payload(EntryBeginPayload {
            entry_id: entry.entry_id,
            kind: entry.kind,
            path: &entry.path,
            mode: entry.mode,
            mtime_sec: entry.mtime_sec,
            mtime_nsec: entry.mtime_nsec,
            atime_sec: entry.atime_sec,
            atime_nsec: entry.atime_nsec,
            size: if entry.kind == 0 {
                Some(entry.size)
            } else {
                None
            },
            file_codec: if entry.kind == 0 { entry.file_codec } else { None },
            chunk_size: if entry.kind == 0 { entry.chunk_size } else { None },
            symlink_target: entry.symlink_target.as_deref(),
        })?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| AmberError::Invalid("Archive not open".into()))?;
        write_record(
            file,
            RTYPE_ENTRY_BEGIN,
            0,
            b"",
            &payload,
            self.encryptor.as_ref(),
        )?;
        Ok(())
    }

    fn write_entry_end(&mut self, entry_id: u64, total_chunks: u32) -> AmberResult<()> {
        let hdr_ext = [
            entry_id.to_le_bytes().as_slice(),
            total_chunks.to_le_bytes().as_slice(),
        ]
        .concat();
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| AmberError::Invalid("Archive not open".into()))?;
        write_record(
            file,
            RTYPE_ENTRY_END,
            0,
            &hdr_ext,
            b"",
            self.encryptor.as_ref(),
        )?;
        Ok(())
    }

    fn generate_global_parity(&mut self) -> AmberResult<()> {
        let data_indices: Vec<usize> = self
            .symbols
            .iter()
            .filter(|info| !info.is_parity)
            .map(|info| info.symbol_index as usize)
            .collect();
        if data_indices.is_empty() {
            return Ok(());
        }
        let n = data_indices.len();
        let mut target = if let Some(ppm) = self.amcf_epsilon_ppm {
            let base = (n * ppm) / 1_000_000;
            (if n >= 2 { 2 } else { 1 }).max(base)
        } else {
            canonical_global_parity_rows(n).map_err(AmberError::Invalid)?
        };
        if let Some(min_total) = self.min_total_parity_rows {
            target = target.max(min_total);
        }
        let start_seed = self.amcf_parities.len();
        let sampler = GenericGlobalParitySampler::new(
            self.global_parity_scheme,
            self.amcf_seed_base,
            data_indices,
            start_seed + target,
        )
        .map_err(AmberError::Invalid)?;
        let parity_payloads = iter_parity_payloads(
            start_seed,
            target,
            |seed_id| sampler.combination(seed_id),
            &self.symbol_data,
            self.symbol_size as usize,
        )
        .map_err(AmberError::Invalid)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| AmberError::Invalid("Archive not open".into()))?;
        for (seed_id, payload, tag32) in parity_payloads {
            let hdr_ext = build_chunk_header_ext(
                0,
                seed_id as u32,
                self.symbol_size as u32,
                CODEC_AMCF_PARITY,
                &tag32,
                &self.amcf_seed_base,
                0,
            );
            let rflags = RFLAG_CHUNK_TAG_PRESENT | RFLAG_PARITY_RECORD;
            let (off, payload_offset, final_payload) = write_record(
                file,
                RTYPE_CHUNK,
                rflags,
                &hdr_ext,
                &payload,
                self.encryptor.as_ref(),
            )?;
            let symbol_index = self.symbols.len() as u64;
            self.symbols.push(SymbolInfo {
                symbol_index,
                offset: payload_offset,
                record_offset: off,
                length: final_payload.len() as u64,
                tag32,
                stripe_index: -1,
                is_parity: true,
                seed_base: Some(self.amcf_seed_base),
            });
            self.symbol_data
                .insert(symbol_index as usize, final_payload.clone());
            self.amcf_parities.push(AmcfParityInfo {
                symbol_index,
                seed_id: seed_id as u64,
                offset: payload_offset,
                length: final_payload.len() as u64,
                tag32,
                seed_base: self.amcf_seed_base,
                row_count: target as u64,
            });
        }
        Ok(())
    }

    fn compute_merkle_root(&self) -> [u8; 32] {
        compute_merkle_root_for_entries(&self.entries, &self.symbols)
    }
}

impl Drop for ArchiveWriter {
    fn drop(&mut self) {
        self.close();
    }
}

fn compute_merkle_root_for_entries(entries: &[WriterEntry], _symbols: &[SymbolInfo]) -> [u8; 32] {
    let mut leaves = Vec::new();
    for entry in entries {
        if entry.kind != 0 {
            continue;
        }
        for chunk in &entry.chunks {
            leaves.push(merkle_leaf_from_chunk_tag(&chunk.tag32));
        }
    }
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut i = 0usize;
        while i < level.len() {
            let left = level[i];
            if i + 1 >= level.len() {
                next.push(left);
                break;
            }
            next.push(merkle_parent(&left, &level[i + 1]));
            i += 2;
        }
        level = next;
    }
    level[0]
}

fn symbol_tlv_maps(symbols: &[SymbolInfo]) -> Vec<TlvMap> {
    symbols
        .iter()
        .map(|symbol| {
            let mut map = TlvMap::new();
            map.insert("symbol_index".into(), TlvValue::U64(symbol.symbol_index));
            map.insert("offset".into(), TlvValue::U64(symbol.offset));
            map.insert("record_offset".into(), TlvValue::U64(symbol.record_offset));
            map.insert("length".into(), TlvValue::U64(symbol.length));
            map.insert("tag32".into(), TlvValue::Bytes(symbol.tag32.to_vec()));
            map.insert("is_parity".into(), TlvValue::Bool(symbol.is_parity));
            if symbol.stripe_index >= 0 {
                map.insert(
                    "stripe_index".into(),
                    TlvValue::U64(symbol.stripe_index as u64),
                );
            }
            if let Some(seed_base) = symbol.seed_base {
                map.insert("seed_base".into(), TlvValue::Bytes(seed_base.to_vec()));
            }
            map
        })
        .collect()
}

fn anchor_meta_map(symbols: &[SymbolInfo], offset: u64) -> TlvMap {
    let count = 64usize.min(symbols.len());
    let first = if count == 0 {
        0
    } else {
        symbols[symbols.len() - count].symbol_index
    };
    let last = symbols.last().map(|s| s.symbol_index).unwrap_or(0);
    let mut map = TlvMap::new();
    map.insert("offset".into(), TlvValue::U64(offset));
    map.insert("symbol_count".into(), TlvValue::U64(count as u64));
    map.insert("first_symbol".into(), TlvValue::U64(first));
    map.insert("last_symbol".into(), TlvValue::U64(last));
    map
}

fn build_index_payload(
    archive_uuid: [u8; 16],
    default_chunk_size: u32,
    default_codec: u16,
    entries: &[WriterEntry],
    symbols: &[SymbolInfo],
    amcf_parities: &[AmcfParityInfo],
    anchors: &[TlvMap],
    segments_meta: &[TlvMap],
    global_parity_scheme: &str,
    amcf_seed_base: [u8; 16],
    symbol_size: u64,
) -> AmberResult<Vec<u8>> {
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
        TlvValue::U64(default_chunk_size as u64),
    );
    idx_map.insert("default_codec".into(), TlvValue::U64(default_codec as u64));
    idx_map.insert(
        "entries".into(),
        TlvValue::List(
            entries
                .iter()
                .map(|entry| {
                    let mut ent = TlvMap::new();
                    ent.insert("entry_id".into(), TlvValue::U64(entry.entry_id));
                    ent.insert("kind".into(), TlvValue::U64(entry.kind));
                    ent.insert("path".into(), TlvValue::String(entry.path.clone()));
                    if let Some(mode) = entry.mode {
                        ent.insert("mode".into(), TlvValue::U64(mode));
                    }
                    if let Some(mtime_sec) = entry.mtime_sec {
                        ent.insert(
                            "mtime".into(),
                            TlvValue::Map(BTreeMap::from([
                                ("sec".into(), TlvValue::U64(mtime_sec)),
                                ("nsec".into(), TlvValue::U64(entry.mtime_nsec.unwrap_or(0))),
                            ])),
                        );
                    }
                    if let Some(atime_sec) = entry.atime_sec {
                        ent.insert(
                            "atime".into(),
                            TlvValue::Map(BTreeMap::from([
                                ("sec".into(), TlvValue::U64(atime_sec)),
                                ("nsec".into(), TlvValue::U64(entry.atime_nsec.unwrap_or(0))),
                            ])),
                        );
                    }
                    if entry.kind == 0 {
                        ent.insert("size".into(), TlvValue::U64(entry.size));
                        if let Some(file_codec) = entry.file_codec {
                            ent.insert("file_codec".into(), TlvValue::U64(file_codec));
                        }
                        if let Some(chunk_size) = entry.chunk_size {
                            ent.insert("chunk_size".into(), TlvValue::U64(chunk_size));
                        }
                        ent.insert(
                            "chunks".into(),
                            TlvValue::List(
                                entry
                                    .chunks
                                    .iter()
                                    .map(|chunk| {
                                        BTreeMap::from([
                                            ("offset".into(), TlvValue::U64(chunk.offset)),
                                            (
                                                "payload_offset".into(),
                                                TlvValue::U64(chunk.payload_offset),
                                            ),
                                            (
                                                "payload_len".into(),
                                                TlvValue::U64(chunk.payload_len),
                                            ),
                                            (
                                                "uncompressed_len".into(),
                                                TlvValue::U64(chunk.uncompressed_len),
                                            ),
                                            (
                                                "chunk_index".into(),
                                                TlvValue::U64(chunk.chunk_index),
                                            ),
                                            (
                                                "blake3_32".into(),
                                                TlvValue::Bytes(chunk.tag32.to_vec()),
                                            ),
                                        ])
                                    })
                                    .collect(),
                            ),
                        );
                        if let Some(file_hash32) = entry.file_hash32 {
                            ent.insert(
                                "file_blake3_32".into(),
                                TlvValue::Bytes(file_hash32.to_vec()),
                            );
                        }
                    }
                    if entry.kind == 2
                        && let Some(target) = &entry.symlink_target
                    {
                        ent.insert("symlink_target".into(), TlvValue::String(target.clone()));
                    }
                    ent
                })
                .collect(),
        ),
    );
    idx_map.insert(
        "ecc_groups".into(),
        TlvValue::List(vec![{
            let mut group = TlvMap::new();
            group.insert("group_id".into(), TlvValue::U64(1));
            group.insert("symbol_size".into(), TlvValue::U64(symbol_size));
            let data_symbol_count = symbols.iter().filter(|s| !s.is_parity).count();
            let epsilon_ppm = if data_symbol_count > 0 {
                (amcf_parities.len() * 1_000_000 / data_symbol_count) as u64
            } else {
                0
            };
            group.insert(
                "amcf".into(),
                TlvValue::Map({
                    let mut amcf = TlvMap::new();
                    amcf.insert(
                        "scheme".into(),
                        TlvValue::String(global_parity_scheme.into()),
                    );
                    amcf.insert("seed_base".into(), TlvValue::Bytes(amcf_seed_base.to_vec()));
                    amcf.insert("epsilon_ppm".into(), TlvValue::U64(epsilon_ppm));
                    amcf.insert(
                        "parity".into(),
                        TlvValue::List(
                            amcf_parities
                                .iter()
                                .map(|parity| {
                                    BTreeMap::from([
                                        ("symbol_index".into(), TlvValue::U64(parity.symbol_index)),
                                        ("seed_id".into(), TlvValue::U64(parity.seed_id)),
                                        ("offset".into(), TlvValue::U64(parity.offset)),
                                        ("length".into(), TlvValue::U64(parity.length)),
                                        ("tag32".into(), TlvValue::Bytes(parity.tag32.to_vec())),
                                        (
                                            "seed_base".into(),
                                            TlvValue::Bytes(parity.seed_base.to_vec()),
                                        ),
                                        ("row_count".into(), TlvValue::U64(parity.row_count)),
                                    ])
                                })
                                .collect(),
                        ),
                    );
                    amcf
                }),
            );
            group.insert("symbols".into(), TlvValue::List(symbol_tlv_maps(symbols)));
            group
        }]),
    );
    idx_map.insert("anchors".into(), TlvValue::List(anchors.to_vec()));
    idx_map.insert("segments".into(), TlvValue::List(segments_meta.to_vec()));
    dumps_index(&idx_map)
}

fn random_array_16() -> AmberResult<[u8; 16]> {
    let mut out = [0u8; 16];
    fill(&mut out)
        .map_err(|err| AmberError::Invalid(format!("secure randomness unavailable: {err}")))?;
    Ok(out)
}

fn file_times_from_metadata(
    st: &std::fs::Metadata,
) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        return (
            Some(st.mtime() as u64),
            Some(st.mtime_nsec() as u64),
            Some(st.atime() as u64),
            Some(st.atime_nsec() as u64),
        );
    }

    #[allow(unreachable_code)]
    {
        let modified = st
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok());
        let accessed = st
            .accessed()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok());
        (
            modified.map(|d| d.as_secs()),
            modified.map(|d| d.subsec_nanos() as u64),
            accessed.map(|d| d.as_secs()),
            accessed.map(|d| d.subsec_nanos() as u64),
        )
    }
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
#[path = "tests/writer.rs"]
mod tests;

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::archiveio::LogicalArchiveReader;
use crate::codec::Codec;
use crate::constants::{
    CODEC_DEFLATE, FLAG_ENCRYPTED, INDEX_FRAME_MAGIC, INDEX_LOC_MAGIC, KDF_ARGON2ID_V2,
    RTYPE_CHUNK,
};
use crate::crc32c::crc32c;
use crate::encryption::{EncryptionContext, EncryptionParams, derive_user_secret};
use crate::error::{AmberError, AmberResult};
use crate::hashutil::{blake3_32, merkle_leaf_from_chunk_tag, merkle_parent};
use crate::pathutil::{validate_archive_path, validate_symlink_target};
use crate::records::{parse_chunk_header_ext, read_record_at};
use crate::superblock::{Superblock, read_superblock};
use crate::tlv::{
    IndexLimits, TlvMap, get_bool, get_bytes, get_list, get_map, get_string, get_u64, loads_anchor,
    loads_index,
};
use crate::trailer::{INDEX_FRAME_HEADER_SIZE, INDEX_LOCATOR_SIZE};

const MAX_INDEX_UNCOMPRESSED: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkDesc {
    pub offset: u64,
    pub payload_offset: u64,
    pub payload_len: u64,
    pub uncompressed_len: u64,
    pub chunk_index: u64,
    pub tag32: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolInfo {
    pub symbol_index: u64,
    pub offset: u64,
    pub record_offset: u64,
    pub length: u64,
    pub tag32: [u8; 32],
    pub stripe_index: i64,
    pub is_parity: bool,
    pub seed_base: Option<[u8; 16]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmcfParityInfo {
    pub symbol_index: u64,
    pub seed_id: u64,
    pub offset: u64,
    pub length: u64,
    pub tag32: [u8; 32],
    pub seed_base: [u8; 16],
    pub row_count: u64,
}

#[derive(Debug)]
pub struct ArchiveReader {
    pub path: PathBuf,
    pub file: Option<LogicalArchiveReader>,
    pub superblock: Option<Superblock>,
    pub index: Option<TlvMap>,
    pub entries: Vec<Entry>,
    pub index_merkle_root: Option<[u8; 32]>,
    pub segments_meta: Vec<TlvMap>,
    pub symbols: Vec<SymbolInfo>,
    pub symbol_size: u64,
    pub amcf_parities: Vec<AmcfParityInfo>,
    pub anchors_meta: Vec<TlvMap>,
    pub anchors_data: Vec<TlvMap>,
    pub anchor_total_count: usize,
    pub anchor_fail_count: usize,
    pub password: Option<String>,
    pub keyfile: Option<PathBuf>,
    pub decryptor: Option<EncryptionContext>,
    pub index_frame_offset: u64,
    pub index_locator_offset: u64,
    pub index_region_start: u64,
    pub index_frame_len: u64,
}

impl ArchiveReader {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self::new_with_credentials(path, None, None)
    }

    pub fn new_with_credentials(
        path: impl AsRef<Path>,
        password: Option<String>,
        keyfile: Option<PathBuf>,
    ) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            file: None,
            superblock: None,
            index: None,
            entries: Vec::new(),
            index_merkle_root: None,
            segments_meta: Vec::new(),
            symbols: Vec::new(),
            symbol_size: 65_536,
            amcf_parities: Vec::new(),
            anchors_meta: Vec::new(),
            anchors_data: Vec::new(),
            anchor_total_count: 0,
            anchor_fail_count: 0,
            password,
            keyfile,
            decryptor: None,
            index_frame_offset: 0,
            index_locator_offset: 0,
            index_region_start: 0,
            index_frame_len: 0,
        }
    }

    pub fn open(&mut self) -> AmberResult<()> {
        if self.file.is_some() {
            return Ok(());
        }
        let mut file = LogicalArchiveReader::open_path(&self.path)?;
        let superblock = read_superblock(&mut file)?;
        if (superblock.flags & FLAG_ENCRYPTED) != 0 {
            let secret = derive_user_secret(self.password.as_deref(), self.keyfile.as_deref())?
                .ok_or_else(|| {
                    AmberError::EncryptedIndexRequiresPassword(
                        "Archive is encrypted; password or keyfile required".into(),
                    )
                })?;
            if superblock.kdf_id != KDF_ARGON2ID_V2 {
                return Err(AmberError::Invalid(
                    "Unsupported KDF for encrypted archive".into(),
                ));
            }
            self.decryptor = Some(EncryptionContext::from_params_secret(
                &secret,
                EncryptionParams {
                    salt: superblock.kdf_salt,
                    time_cost: superblock.argon_time_cost,
                    memory_cost_kib: superblock.argon_memory_cost,
                    parallelism: superblock.argon_parallelism,
                },
            )?);
        } else {
            self.decryptor = None;
        }
        self.superblock = Some(superblock);
        self.load_index_from(&mut file)?;
        self.file = Some(file);
        Ok(())
    }

    pub fn close(&mut self) {
        self.file = None;
    }

    fn load_index_from(&mut self, file: &mut LogicalArchiveReader) -> AmberResult<()> {
        let size = file.logical_size();
        let scan_chunk = 256 * 1024usize;
        let overlap = INDEX_LOC_MAGIC.len().max(INDEX_LOCATOR_SIZE) - 1;
        let archive_uuid = self
            .superblock
            .as_ref()
            .map(|sb| sb.uuid)
            .unwrap_or([0u8; 16]);

        let mut loc_off = None;
        let mut frame_len = 0u64;
        let mut copy_seq = 0u32;
        let mut frame_off = 0u64;
        let mut pos = size;
        let mut carry = Vec::new();

        while pos > 0 && loc_off.is_none() {
            let start = pos.saturating_sub(scan_chunk as u64);
            file.seek(SeekFrom::Start(start))?;
            let mut chunk = vec![0u8; usize::try_from(pos - start).unwrap()];
            file.read_exact(&mut chunk)?;
            let mut window = chunk.clone();
            window.extend_from_slice(&carry);
            let mut scan_pos = window.len();
            while let Some(found) = rfind_bytes(&window[..scan_pos], &INDEX_LOC_MAGIC) {
                let candidate_off = start + found as u64;
                file.seek(SeekFrom::Start(candidate_off))?;
                let mut loc_raw = [0u8; INDEX_LOCATOR_SIZE];
                match file.read_exact(&mut loc_raw) {
                    Ok(()) => {}
                    Err(_) => {
                        scan_pos = found;
                        continue;
                    }
                }
                let loc_magic = &loc_raw[..8];
                let fl = u64::from_le_bytes(loc_raw[8..16].try_into().unwrap());
                let foff = u64::from_le_bytes(loc_raw[16..24].try_into().unwrap());
                let seq = u32::from_le_bytes(loc_raw[24..28].try_into().unwrap());
                let mut loc_uuid = [0u8; 16];
                loc_uuid.copy_from_slice(&loc_raw[28..44]);
                let loc_crc = u32::from_le_bytes(loc_raw[44..48].try_into().unwrap());
                if loc_magic != INDEX_LOC_MAGIC {
                    scan_pos = found;
                    continue;
                }
                let mut crc_payload = Vec::with_capacity(44);
                crc_payload.extend_from_slice(&INDEX_LOC_MAGIC);
                crc_payload.extend_from_slice(&fl.to_le_bytes());
                crc_payload.extend_from_slice(&foff.to_le_bytes());
                crc_payload.extend_from_slice(&seq.to_le_bytes());
                crc_payload.extend_from_slice(&loc_uuid);
                if crc32c(&crc_payload, 0) != loc_crc {
                    scan_pos = found;
                    continue;
                }
                if archive_uuid != [0u8; 16] && loc_uuid != archive_uuid {
                    scan_pos = found;
                    continue;
                }
                loc_off = Some(candidate_off);
                frame_len = fl;
                copy_seq = seq;
                frame_off = foff;
                break;
            }
            pos = start;
            carry = chunk.into_iter().take(overlap).collect();
        }

        let loc_off = loc_off.ok_or_else(|| {
            AmberError::IndexLocator("Index locator not found or CRC mismatch".into())
        })?;

        file.seek(SeekFrom::Start(frame_off))?;
        let mut frame_body = vec![
            0u8;
            usize::try_from(frame_len).map_err(|_| AmberError::Invalid(
                "index frame length too large".into()
            ))?
        ];
        file.read_exact(&mut frame_body)?;

        self.index_frame_offset = frame_off;
        self.index_locator_offset = loc_off;
        self.index_frame_len = frame_len;
        self.index_region_start = if copy_seq == 1 {
            frame_off.saturating_sub(frame_len)
        } else {
            frame_off
        };

        let frame_body = match self.decryptor.as_ref() {
            Some(decryptor) => {
                decryptor.decrypt(b"IDXFRAME", &frame_body, &frame_off.to_le_bytes())?
            }
            None => frame_body,
        };
        if frame_body.len() < 4 {
            return Err(AmberError::IndexFrame("Index frame too short".into()));
        }
        let frame_crc = u32::from_le_bytes(frame_body[frame_body.len() - 4..].try_into().unwrap());
        if crc32c(&frame_body[..frame_body.len() - 4], 0) != frame_crc {
            return Err(AmberError::IndexFrame("Index frame CRC mismatch".into()));
        }
        if frame_body.len() < INDEX_FRAME_HEADER_SIZE + 4 {
            return Err(AmberError::IndexFrame("Index frame too short".into()));
        }
        let frame_magic = &frame_body[..8];
        let frame_flags = u32::from_le_bytes(frame_body[8..12].try_into().unwrap());
        let uncompressed_len = u64::from_le_bytes(frame_body[12..20].try_into().unwrap());
        let mut index_hash = [0u8; 32];
        index_hash.copy_from_slice(&frame_body[20..52]);
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&frame_body[52..84]);
        if frame_magic != INDEX_FRAME_MAGIC {
            return Err(AmberError::IndexFrame("Bad index frame magic".into()));
        }
        if self.decryptor.is_none() && (frame_flags & 2) != 0 {
            return Err(AmberError::EncryptedIndexRequiresPassword(
                "Encrypted index frame requires password".into(),
            ));
        }
        if uncompressed_len > MAX_INDEX_UNCOMPRESSED {
            return Err(AmberError::IndexSize(
                "Index size exceeds safety bound".into(),
            ));
        }

        let payload = &frame_body[INDEX_FRAME_HEADER_SIZE..frame_body.len() - 4];
        let decoded_payload = if (frame_flags & 1) != 0 {
            Codec::new(CODEC_DEFLATE).decompress(
                payload,
                Some(usize::try_from(uncompressed_len).map_err(|_| {
                    AmberError::Invalid("index size exceeds platform limit".into())
                })?),
            )?
        } else {
            payload.to_vec()
        };
        if decoded_payload.len() as u64 != uncompressed_len {
            return Err(AmberError::IndexLengthMismatch(
                "Index uncompressed length mismatch".into(),
            ));
        }
        if blake3_32(&decoded_payload) != index_hash {
            return Err(AmberError::IndexHashMismatch("Index hash mismatch".into()));
        }
        let idx = loads_index(&decoded_payload, IndexLimits::default())?;
        self.segments_meta = get_list(&idx, "segments").cloned().unwrap_or_default();
        self.anchors_meta = get_list(&idx, "anchors").cloned().unwrap_or_default();
        self.validate_segments_metadata(file)?;
        self.entries = self.build_entries(&idx, size)?;
        let calc = self.compute_merkle_from_index();
        if calc != merkle_root {
            return Err(AmberError::MerkleMismatch(
                "Index Merkle root mismatch".into(),
            ));
        }
        self.load_ecc_groups(&idx, size)?;
        self.load_anchor_records(file)?;
        self.index = Some(idx);
        self.index_merkle_root = Some(merkle_root);
        Ok(())
    }

    pub fn list(&self) -> &[Entry] {
        &self.entries
    }

    pub fn extract(&mut self, entry: &Entry, out_path: impl AsRef<Path>) -> AmberResult<()> {
        let Some(file) = self.file.as_mut() else {
            return Err(AmberError::Invalid("Archive not open".into()));
        };
        if entry.kind != 0 {
            return Ok(());
        }
        if let Some(parent) = out_path.as_ref().parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = std::fs::File::create(out_path)?;
        for chunk in &entry.chunks {
            let record = read_record_at(file, chunk.offset, self.decryptor.as_ref())?;
            if record.rtype != RTYPE_CHUNK {
                return Err(AmberError::Invalid("Expected chunk record".into()));
            }
            let (_eid, _idx, _ulen, codec_id, _flags, tag32, _aux16) =
                parse_chunk_header_ext(&record.header_ext)?;
            let codec = Codec::new(codec_id);
            let raw = codec.decompress(
                &record.payload,
                Some(
                    usize::try_from(chunk.uncompressed_len)
                        .map_err(|_| AmberError::Invalid("chunk length too large".into()))?,
                ),
            )?;
            if raw.len() as u64 != chunk.uncompressed_len {
                return Err(AmberError::Invalid(
                    "Chunk length mismatch after decompress".into(),
                ));
            }
            if blake3_32(&raw) != tag32 {
                return Err(AmberError::Invalid(
                    "Chunk tag mismatch; data corrupted".into(),
                ));
            }
            use std::io::Write;
            out.write_all(&raw)?;
        }
        Ok(())
    }

    pub fn verify(&mut self) -> AmberResult<bool> {
        let Some(file) = self.file.as_mut() else {
            return Err(AmberError::Invalid("Archive not open".into()));
        };
        let mut ok = true;
        for entry in &self.entries {
            if entry.kind != 0 {
                continue;
            }
            let mut file_bytes = Vec::new();
            for chunk in &entry.chunks {
                let record = match read_record_at(file, chunk.offset, self.decryptor.as_ref()) {
                    Ok(record) => record,
                    Err(_) => {
                        ok = false;
                        continue;
                    }
                };
                let (_eid, _idx, _ulen, codec_id, _flags, tag32, _aux16) =
                    match parse_chunk_header_ext(&record.header_ext) {
                        Ok(parsed) => parsed,
                        Err(_) => {
                            ok = false;
                            continue;
                        }
                    };
                let raw = match Codec::new(codec_id).decompress(
                    &record.payload,
                    Some(
                        usize::try_from(chunk.uncompressed_len)
                            .map_err(|_| AmberError::Invalid("chunk length too large".into()))?,
                    ),
                ) {
                    Ok(raw) => raw,
                    Err(_) => {
                        ok = false;
                        continue;
                    }
                };
                if blake3_32(&raw) != tag32 {
                    ok = false;
                }
                file_bytes.extend_from_slice(&raw);
            }
            if let Some(file_hash32) = entry.file_hash32
                && blake3_32(&file_bytes) != file_hash32
            {
                ok = false;
            }
        }
        if let Some(index_merkle_root) = self.index_merkle_root
            && self.compute_merkle_from_index() != index_merkle_root
        {
            ok = false;
        }
        Ok(ok)
    }
}

impl Drop for ArchiveReader {
    fn drop(&mut self) {
        self.close();
    }
}

fn rfind_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&idx| &haystack[idx..idx + needle.len()] == needle)
}

impl ArchiveReader {
    fn validate_segments_metadata(&self, file: &LogicalArchiveReader) -> AmberResult<()> {
        if self.segments_meta.is_empty() {
            return Err(AmberError::ChunkBounds(
                "Index is missing segments metadata".into(),
            ));
        }
        let actual_segments = file.segments();
        if self.segments_meta.len() != actual_segments.len() {
            return Err(AmberError::ChunkBounds(
                "Index segment metadata does not match physical segment count".into(),
            ));
        }
        let mut expected_index = 1u64;
        for (meta, actual) in self.segments_meta.iter().zip(actual_segments.iter()) {
            let segment_index = get_u64(meta, "segment_index").unwrap_or(0);
            let physical_header_length =
                get_u64(meta, "physical_header_length").unwrap_or(u64::MAX);
            if segment_index != expected_index {
                return Err(AmberError::ChunkBounds(
                    "Index segment numbering is not contiguous".into(),
                ));
            }
            if physical_header_length != actual.physical_header_length {
                return Err(AmberError::ChunkBounds(
                    "Index segment physical header length mismatch".into(),
                ));
            }
            expected_index += 1;
        }
        Ok(())
    }

    fn build_entries(&self, idx: &TlvMap, archive_size: u64) -> AmberResult<Vec<Entry>> {
        let mut entries = Vec::new();
        for ent in get_list(idx, "entries").cloned().unwrap_or_default() {
            let path = validate_archive_path(
                get_string(&ent, "path")
                    .ok_or_else(|| AmberError::Invalid("entry is missing path".into()))?,
            )?;
            if path.len() > 1024 {
                return Err(AmberError::Invalid("Path length exceeds 1024 bytes".into()));
            }
            let kind = get_u64(&ent, "kind").unwrap_or(0);
            let mut entry = Entry {
                entry_id: get_u64(&ent, "entry_id").unwrap_or(0),
                kind,
                path,
                size: get_u64(&ent, "size").unwrap_or(0),
                mode: get_u64(&ent, "mode"),
                mtime_sec: get_map(&ent, "mtime").and_then(|m| get_u64(m, "sec")),
                mtime_nsec: get_map(&ent, "mtime").and_then(|m| get_u64(m, "nsec")),
                atime_sec: get_map(&ent, "atime").and_then(|m| get_u64(m, "sec")),
                atime_nsec: get_map(&ent, "atime").and_then(|m| get_u64(m, "nsec")),
                file_codec: get_u64(&ent, "file_codec"),
                chunk_size: get_u64(&ent, "chunk_size"),
                chunks: Vec::new(),
                file_hash32: get_bytes(&ent, "file_blake3_32").map(copy_32),
                symlink_target: None,
            };
            if kind == 0 {
                for ch in get_list(&ent, "chunks").cloned().unwrap_or_default() {
                    let uncompressed_len = get_u64(&ch, "uncompressed_len").unwrap_or(0);
                    if let Some(chunk_size) = entry.chunk_size
                        && uncompressed_len > chunk_size
                    {
                        return Err(AmberError::ChunkBounds(
                            "Chunk uncompressed_len exceeds declared chunk_size".into(),
                        ));
                    }
                    let offset = get_u64(&ch, "offset").unwrap_or(0);
                    let payload_offset = get_u64(&ch, "payload_offset").unwrap_or(0);
                    let payload_len = get_u64(&ch, "payload_len").unwrap_or(0);
                    if offset >= archive_size {
                        return Err(AmberError::ChunkBounds("Chunk offset out of range".into()));
                    }
                    if payload_offset >= archive_size {
                        return Err(AmberError::ChunkBounds(
                            "Chunk payload_offset out of range".into(),
                        ));
                    }
                    if payload_offset
                        .checked_add(payload_len)
                        .is_none_or(|end| end > archive_size)
                    {
                        return Err(AmberError::ChunkBounds(
                            "Chunk payload length out of range".into(),
                        ));
                    }
                    entry.chunks.push(ChunkDesc {
                        offset,
                        payload_offset,
                        payload_len,
                        uncompressed_len,
                        chunk_index: get_u64(&ch, "chunk_index").unwrap_or(0),
                        tag32: copy_32(get_bytes(&ch, "blake3_32").ok_or_else(|| {
                            AmberError::Invalid("chunk is missing blake3_32".into())
                        })?),
                    });
                }
            }
            if kind == 2
                && let Some(target) = get_string(&ent, "symlink_target")
            {
                entry.symlink_target = Some(validate_symlink_target(target)?);
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    fn compute_merkle_from_index(&self) -> [u8; 32] {
        let mut leaves = Vec::new();
        for entry in &self.entries {
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
            let mut idx = 0usize;
            while idx < level.len() {
                let left = level[idx];
                if idx + 1 >= level.len() {
                    next.push(left);
                    break;
                }
                let right = level[idx + 1];
                next.push(merkle_parent(&left, &right));
                idx += 2;
            }
            level = next;
        }
        level[0]
    }

    fn load_ecc_groups(&mut self, idx: &TlvMap, archive_size: u64) -> AmberResult<()> {
        self.symbols.clear();
        self.amcf_parities.clear();
        let groups = get_list(idx, "ecc_groups").cloned().unwrap_or_default();
        if groups.is_empty() {
            return Ok(());
        }

        let mut symbol_map = std::collections::BTreeMap::new();
        self.symbol_size = get_u64(&groups[0], "symbol_size").unwrap_or(65_536);

        for group in groups {
            if get_u64(&group, "symbol_size").unwrap_or(self.symbol_size) != self.symbol_size {
                return Err(AmberError::SymbolSizeMismatch(
                    "Mismatched symbol_size across ECC groups".into(),
                ));
            }

            for sym in get_list(&group, "symbols").cloned().unwrap_or_default() {
                let record_offset = get_u64(&sym, "record_offset").ok_or_else(|| {
                    AmberError::Invalid("ECC symbol missing record_offset in index".into())
                })?;
                let length = get_u64(&sym, "length").unwrap_or(0);
                let offset = get_u64(&sym, "offset").unwrap_or(0);
                let info = SymbolInfo {
                    symbol_index: get_u64(&sym, "symbol_index").unwrap_or(0),
                    offset,
                    record_offset,
                    length,
                    tag32: get_bytes(&sym, "tag32").map(copy_32).unwrap_or([0u8; 32]),
                    stripe_index: get_u64(&sym, "stripe_index")
                        .map(|v| v as i64)
                        .unwrap_or(-1),
                    is_parity: get_bool(&sym, "is_parity").unwrap_or(false),
                    seed_base: get_bytes(&sym, "seed_base").map(copy_16),
                };
                let mut max_len = self.symbol_size;
                if info.is_parity && self.decryptor.is_some() {
                    max_len += self
                        .decryptor
                        .as_ref()
                        .map_or(0, |decryptor| decryptor.overhead() as u64);
                }
                if info.length > max_len {
                    return Err(AmberError::SymbolBounds(
                        "ECC symbol length out of range".into(),
                    ));
                }
                if info
                    .offset
                    .checked_add(info.length)
                    .is_none_or(|end| end > archive_size)
                {
                    return Err(AmberError::SymbolBounds(
                        "ECC symbol offset/length out of range".into(),
                    ));
                }
                if symbol_map.insert(info.symbol_index, info).is_some() {
                    return Err(AmberError::DuplicateSymbolIndex(
                        "Duplicate ECC symbol index across groups".into(),
                    ));
                }
            }

            if let Some(amcf) = get_map(&group, "amcf") {
                let group_seed_base = get_bytes(amcf, "seed_base")
                    .map(copy_16)
                    .unwrap_or([0u8; 16]);
                let group_parity = get_list(amcf, "parity").cloned().unwrap_or_default();
                let group_row_count = group_parity.len() as u64;
                for item in group_parity {
                    self.amcf_parities.push(AmcfParityInfo {
                        symbol_index: get_u64(&item, "symbol_index").unwrap_or(0),
                        seed_id: get_u64(&item, "seed_id").unwrap_or(0),
                        offset: get_u64(&item, "offset").unwrap_or(0),
                        length: get_u64(&item, "length").unwrap_or(self.symbol_size),
                        tag32: get_bytes(&item, "tag32").map(copy_32).unwrap_or([0u8; 32]),
                        seed_base: get_bytes(&item, "seed_base")
                            .map(copy_16)
                            .unwrap_or(group_seed_base),
                        row_count: get_u64(&item, "row_count").unwrap_or(group_row_count),
                    });
                }
            }
        }

        if let Some(max_index) = symbol_map.keys().next_back().copied() {
            for index in 0..=max_index {
                let info = symbol_map.remove(&index).ok_or_else(|| {
                    AmberError::SymbolIndexGap("ECC symbol index gap detected".into())
                })?;
                self.symbols.push(info);
            }
        }

        Ok(())
    }

    fn load_anchor_records(&mut self, file: &mut LogicalArchiveReader) -> AmberResult<()> {
        self.anchors_data.clear();
        self.anchor_total_count = 0;
        self.anchor_fail_count = 0;
        if self.anchors_meta.is_empty() {
            return Ok(());
        }
        for meta in &self.anchors_meta {
            let Some(offset) = get_u64(meta, "offset") else {
                continue;
            };
            self.anchor_total_count += 1;
            let record = match read_record_at(file, offset, self.decryptor.as_ref()) {
                Ok(record) => record,
                Err(_) => {
                    self.anchor_fail_count += 1;
                    continue;
                }
            };
            if record.rtype != crate::constants::RTYPE_ANCHOR {
                self.anchor_fail_count += 1;
                continue;
            }
            let mut anchor = match loads_anchor(&record.payload, 1024) {
                Ok(anchor) => anchor,
                Err(_) => {
                    self.anchor_fail_count += 1;
                    continue;
                }
            };
            anchor.insert("offset".into(), crate::tlv::TlvValue::U64(offset));
            self.anchors_data.push(anchor);
        }
        Ok(())
    }
}

fn copy_32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

fn copy_16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    out
}

#[cfg(test)]
#[path = "tests/reader.rs"]
mod tests;

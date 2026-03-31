use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::archiveio::LogicalArchiveReader;
use crate::error::{AmberError, AmberResult};
use crate::reader::ArchiveReader;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkTarget {
    pub kind: &'static str,
    pub ordinal: usize,
    pub record_offset: u64,
    pub payload_offset: u64,
    pub payload_len: u64,
    pub label: String,
}

fn flip_byte(path: &Path, offset: u64) -> AmberResult<()> {
    let mut file = LogicalArchiveReader::open_path_rw(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut byte = [0u8; 1];
    let read = file.read(&mut byte)?;
    if read == 0 {
        return Err(AmberError::Invalid("Offset beyond end of logical archive".into()));
    }
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&[byte[0] ^ 0xFF])?;
    file.flush()?;
    file.sync()?;
    Ok(())
}

fn flip_chunk_payload_byte(path: &Path, target: &ChunkTarget, within: u64) -> AmberResult<()> {
    if within >= target.payload_len {
        return Err(AmberError::Invalid(format!(
            "--within must be within chunk payload length for {} (0..{})",
            target.label,
            target.payload_len.saturating_sub(1)
        )));
    }
    flip_byte(path, target.payload_offset + within)
}

pub fn load_chunk_targets(
    archive: &Path,
    password: Option<&str>,
    keyfile: Option<&Path>,
    include_parity: bool,
) -> AmberResult<Vec<ChunkTarget>> {
    let mut reader = ArchiveReader::new_with_credentials(
        archive,
        password.map(str::to_owned),
        keyfile.map(Path::to_path_buf),
    );
    reader.open()?;

    let mut targets = Vec::new();
    for entry in &reader.entries {
        if entry.kind != 0 {
            continue;
        }
        for chunk in &entry.chunks {
            targets.push(ChunkTarget {
                kind: "data",
                ordinal: targets.len(),
                record_offset: chunk.offset,
                payload_offset: chunk.payload_offset,
                payload_len: chunk.payload_len,
                label: format!("data:{}:{}", entry.path, chunk.chunk_index),
            });
        }
    }

    if include_parity {
        let mut seen_offsets = targets
            .iter()
            .map(|target| target.record_offset)
            .collect::<std::collections::BTreeSet<_>>();
        let mut parity_symbols = reader
            .symbols
            .iter()
            .filter(|sym| sym.is_parity)
            .cloned()
            .collect::<Vec<_>>();
        parity_symbols.sort_by_key(|sym| sym.record_offset);
        for sym in parity_symbols {
            if seen_offsets.contains(&sym.record_offset) {
                continue;
            }
            targets.push(ChunkTarget {
                kind: "parity",
                ordinal: targets.len(),
                record_offset: sym.record_offset,
                payload_offset: sym.offset,
                payload_len: sym.length,
                label: format!("parity:{}", sym.symbol_index),
            });
            seen_offsets.insert(sym.record_offset);
        }
    }

    Ok(targets)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorruptResult {
    pub labels: Vec<String>,
    pub message: String,
}

pub fn corrupt_by_offset(archive: &Path, offset: u64) -> AmberResult<CorruptResult> {
    flip_byte(archive, offset)?;
    Ok(CorruptResult {
        labels: Vec::new(),
        message: format!("Flipped 1 byte at offset {offset}"),
    })
}

pub fn corrupt_first_symbol(
    archive: &Path,
    within: u64,
    include_parity: bool,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<CorruptResult> {
    let mut reader = ArchiveReader::new_with_credentials(
        archive,
        password.map(str::to_owned),
        keyfile.map(Path::to_path_buf),
    );
    reader.open()?;
    let sym = reader
        .symbols
        .iter()
        .find(|sym| include_parity || !sym.is_parity)
        .ok_or_else(|| AmberError::Invalid("No suitable symbol found in archive".into()))?;
    if within >= sym.length {
        return Err(AmberError::Invalid(format!(
            "--within must be within symbol length (0..{})",
            sym.length.saturating_sub(1)
        )));
    }
    let off = sym.offset + within;
    flip_byte(archive, off)?;
    Ok(CorruptResult {
        labels: vec![sym.symbol_index.to_string()],
        message: format!(
            "Flipped 1 byte in symbol {} at archive offset {}",
            sym.symbol_index, off
        ),
    })
}

pub fn corrupt_symbol(
    archive: &Path,
    index: usize,
    within: u64,
    include_parity: bool,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<CorruptResult> {
    let mut reader = ArchiveReader::new_with_credentials(
        archive,
        password.map(str::to_owned),
        keyfile.map(Path::to_path_buf),
    );
    reader.open()?;
    if index >= reader.symbols.len() {
        return Err(AmberError::Invalid(format!(
            "Symbol index out of range (0..{})",
            reader.symbols.len().saturating_sub(1)
        )));
    }
    let sym = &reader.symbols[index];
    if !include_parity && sym.is_parity {
        return Err(AmberError::Invalid(
            "Selected symbol is parity; pass --include-parity to allow".into(),
        ));
    }
    if within >= sym.length {
        return Err(AmberError::Invalid(format!(
            "--within must be within symbol length (0..{})",
            sym.length.saturating_sub(1)
        )));
    }
    let off = sym.offset + within;
    flip_byte(archive, off)?;
    Ok(CorruptResult {
        labels: vec![index.to_string()],
        message: format!("Flipped 1 byte in symbol {index} at archive offset {off}"),
    })
}

pub fn corrupt_random_chunks(
    archive: &Path,
    count: usize,
    seed: Option<u64>,
    within: u64,
    include_parity: bool,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<CorruptResult> {
    let targets = load_chunk_targets(archive, password, keyfile, include_parity)?;
    if count > targets.len() {
        return Err(AmberError::Invalid(format!(
            "--count exceeds available chunks ({})",
            targets.len()
        )));
    }
    let chosen = choose_random_subset(&targets, count, seed)?;
    for target in &chosen {
        flip_chunk_payload_byte(archive, target, within)?;
    }
    let labels = chosen.iter().map(|target| target.label.clone()).collect::<Vec<_>>();
    Ok(CorruptResult {
        message: format!(
            "Flipped 1 byte in {} randomly selected chunk(s): {:?}",
            chosen.len(),
            labels
        ),
        labels,
    })
}

pub fn corrupt_chunk_window(
    archive: &Path,
    start: usize,
    count: usize,
    within: u64,
    include_parity: bool,
    password: Option<&str>,
    keyfile: Option<&Path>,
) -> AmberResult<CorruptResult> {
    let targets = load_chunk_targets(archive, password, keyfile, include_parity)?;
    let end = start
        .checked_add(count)
        .ok_or_else(|| AmberError::Invalid("Requested chunk window overflows".into()))?;
    if end > targets.len() {
        return Err(AmberError::Invalid(format!(
            "Requested chunk window {}..{} exceeds available chunks (0..{})",
            start,
            end.saturating_sub(1),
            targets.len().saturating_sub(1)
        )));
    }
    let chosen = targets[start..end].to_vec();
    for target in &chosen {
        flip_chunk_payload_byte(archive, target, within)?;
    }
    let labels = chosen.iter().map(|target| target.label.clone()).collect::<Vec<_>>();
    Ok(CorruptResult {
        message: format!(
            "Flipped 1 byte in chunk window {}..{}: {:?}",
            start,
            end.saturating_sub(1),
            labels
        ),
        labels,
    })
}

fn choose_random_subset(
    targets: &[ChunkTarget],
    count: usize,
    seed: Option<u64>,
) -> AmberResult<Vec<ChunkTarget>> {
    let mut indexed = targets.to_vec();
    let mut rng = XorShift64::new(seed.unwrap_or(random_seed()?));
    for idx in (1..indexed.len()).rev() {
        let swap_with = (rng.next_u64() as usize) % (idx + 1);
        indexed.swap(idx, swap_with);
    }
    indexed.truncate(count);
    Ok(indexed)
}

fn random_seed() -> AmberResult<u64> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|err| AmberError::Invalid(format!("secure randomness unavailable: {err}")))?;
    Ok(u64::from_le_bytes(bytes))
}

#[derive(Clone, Copy, Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let seed = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

use std::io::{Seek, Write};

use flate2::{Compression, write::ZlibEncoder};

use crate::archiveio::{ArchiveSegment, LogicalArchiveAppender, LogicalArchiveWriter};
use crate::constants::{INDEX_FRAME_MAGIC, INDEX_LOC_MAGIC};
use crate::crc32c::crc32c;
use crate::encryption::EncryptionContext;
use crate::error::{AmberError, AmberResult};
use crate::hashutil::blake3_32;
use crate::tlv::{TlvMap, TlvValue, dumps_anchor};

pub const INDEX_FRAME_HEADER_SIZE: usize = 84;
pub const INDEX_LOCATOR_SIZE: usize = 48;

pub fn build_anchor_payload(
    symbols: &[TlvMap],
    symbol_size: u64,
    merkle_root: [u8; 32],
    seed_base: Option<&[u8]>,
    scheme: Option<&str>,
) -> TlvMap {
    let start = symbols.len().saturating_sub(64);
    let mut payload = TlvMap::new();
    payload.insert("version".into(), TlvValue::U64(1));
    payload.insert("symbol_size".into(), TlvValue::U64(symbol_size));
    payload.insert("merkle_root".into(), TlvValue::Bytes(merkle_root.to_vec()));
    if let Some(seed_base) = seed_base {
        payload.insert("seed_base".into(), TlvValue::Bytes(seed_base.to_vec()));
    }
    if let Some(scheme) = scheme {
        payload.insert("scheme".into(), TlvValue::String(scheme.to_owned()));
    }
    payload.insert("symbols".into(), TlvValue::List(symbols[start..].to_vec()));
    payload
}

pub fn write_anchor_record<W: crate::records::RecordWriteTarget>(
    writer: &mut W,
    payload: &TlvMap,
    encryptor: Option<&EncryptionContext>,
) -> AmberResult<u64> {
    let encoded = dumps_anchor(payload)?;
    let (off, _, _) = crate::records::write_record(
        writer,
        crate::constants::RTYPE_ANCHOR,
        0,
        b"",
        &encoded,
        encryptor,
    )?;
    Ok(off)
}

pub fn write_index_trailer<W: Write + Seek>(
    writer: &mut W,
    encryptor: Option<&EncryptionContext>,
    archive_uuid: [u8; 16],
    index_payload: &[u8],
    merkle_root: [u8; 32],
) -> AmberResult<()> {
    let (frame_plain, _) = build_frame_plain(index_payload, merkle_root, encryptor.is_some())?;
    let mut frame_locs = Vec::new();
    for seq in [0u32, 1u32] {
        let frame_start = writer.stream_position()?;
        let frame = match encryptor {
            Some(encryptor) => {
                encryptor.encrypt(b"IDXFRAME", &frame_plain, &frame_start.to_le_bytes())?
            }
            None => frame_plain.clone(),
        };
        writer.write_all(&frame)?;
        flush_and_sync(writer)?;
        frame_locs.push((seq, frame_start, frame.len() as u64));
    }
    for (seq, frame_start, frame_len) in frame_locs {
        let locator = build_locator(frame_len, frame_start, seq, archive_uuid);
        writer.write_all(&locator)?;
    }
    flush_and_sync(writer)
}

pub fn write_index_trailer_with_segments<F>(
    writer: &mut LogicalArchiveWriter,
    encryptor: Option<&EncryptionContext>,
    archive_uuid: [u8; 16],
    merkle_root: [u8; 32],
    build_index_payload: F,
) -> AmberResult<Vec<u8>>
where
    F: Fn(&[TlvMap]) -> AmberResult<Vec<u8>>,
{
    let segments = writer.segments().to_vec();
    let repeated_segment_header_length = writer.repeated_segment_header_length();
    let part_size = writer.part_size();
    write_index_trailer_with_segments_inner(
        writer,
        encryptor,
        archive_uuid,
        merkle_root,
        build_index_payload,
        &segments,
        repeated_segment_header_length,
        part_size,
    )
}

pub fn write_index_trailer_with_segments_appender<F>(
    writer: &mut LogicalArchiveAppender,
    encryptor: Option<&EncryptionContext>,
    archive_uuid: [u8; 16],
    merkle_root: [u8; 32],
    build_index_payload: F,
) -> AmberResult<Vec<u8>>
where
    F: Fn(&[TlvMap]) -> AmberResult<Vec<u8>>,
{
    let segments = writer.segments().to_vec();
    let repeated_segment_header_length = writer.repeated_segment_header_length();
    let part_size = writer.part_size();
    write_index_trailer_with_segments_inner(
        writer,
        encryptor,
        archive_uuid,
        merkle_root,
        build_index_payload,
        &segments,
        repeated_segment_header_length,
        part_size,
    )
}

fn write_index_trailer_with_segments_inner<W, F>(
    writer: &mut W,
    encryptor: Option<&EncryptionContext>,
    archive_uuid: [u8; 16],
    merkle_root: [u8; 32],
    build_index_payload: F,
    current_segments: &[ArchiveSegment],
    repeated_segment_header_length: u64,
    part_size: Option<u64>,
) -> AmberResult<Vec<u8>>
where
    W: crate::records::RecordWriteTarget,
    F: Fn(&[TlvMap]) -> AmberResult<Vec<u8>>,
{
    if current_segments.is_empty() {
        return Err(AmberError::Invalid(
            "segment-aware trailer writing requires a logical archive handle".into(),
        ));
    }
    let mut final_segment_count = current_segments.len();
    let (frame_plain, logical_append_bytes, index_payload) = loop {
        let segment_meta = segment_metadata_for_count(
            current_segments,
            final_segment_count,
            repeated_segment_header_length,
        );
        let index_payload = build_index_payload(&segment_meta)?;
        let (frame_plain, _) = build_frame_plain(&index_payload, merkle_root, encryptor.is_some())?;
        let encrypted_frame_len =
            frame_plain.len() as u64 + encryptor.map_or(0, EncryptionContext::overhead) as u64;
        let logical_append_bytes = (2 * encrypted_frame_len) + (2 * INDEX_LOCATOR_SIZE as u64);
        let required_count = required_segment_count(
            current_segments,
            part_size,
            repeated_segment_header_length,
            logical_append_bytes,
        )?;
        if required_count == final_segment_count {
            break (frame_plain, logical_append_bytes, index_payload);
        }
        final_segment_count = required_count;
    };

    writer.reserve_contiguous(logical_append_bytes)?;

    let mut frame_locs = Vec::new();
    for seq in [0u32, 1u32] {
        let frame_start = writer.stream_position()?;
        let frame = match encryptor {
            Some(encryptor) => {
                encryptor.encrypt(b"IDXFRAME", &frame_plain, &frame_start.to_le_bytes())?
            }
            None => frame_plain.clone(),
        };
        writer.write_all(&frame)?;
        flush_and_sync(writer)?;
        frame_locs.push((seq, frame_start, frame.len() as u64));
    }
    for (seq, frame_start, frame_len) in frame_locs {
        let locator = build_locator(frame_len, frame_start, seq, archive_uuid);
        writer.write_all(&locator)?;
    }
    flush_and_sync(writer)?;
    Ok(index_payload)
}

fn flush_and_sync<W: Write + Seek>(writer: &mut W) -> AmberResult<()> {
    writer.flush()?;
    Ok(())
}

fn build_frame_plain(
    index_payload: &[u8],
    merkle_root: [u8; 32],
    encrypted: bool,
) -> AmberResult<(Vec<u8>, u32)> {
    let mut frame_flags = 0u32;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(index_payload)?;
    let compressed = encoder.finish()?;
    let payload = if compressed.len() < index_payload.len() {
        frame_flags |= 1;
        compressed
    } else {
        index_payload.to_vec()
    };
    if encrypted {
        frame_flags |= 2;
    }
    let index_hash = blake3_32(index_payload);
    let mut frame_plain = Vec::with_capacity(INDEX_FRAME_HEADER_SIZE + payload.len() + 4);
    frame_plain.extend_from_slice(&INDEX_FRAME_MAGIC);
    frame_plain.extend_from_slice(&frame_flags.to_le_bytes());
    frame_plain.extend_from_slice(&(index_payload.len() as u64).to_le_bytes());
    frame_plain.extend_from_slice(&index_hash);
    frame_plain.extend_from_slice(&merkle_root);
    frame_plain.extend_from_slice(&payload);
    let frame_crc = crc32c(&frame_plain, 0);
    frame_plain.extend_from_slice(&frame_crc.to_le_bytes());
    Ok((frame_plain, frame_flags))
}

fn build_locator(
    frame_len: u64,
    frame_start: u64,
    seq: u32,
    archive_uuid: [u8; 16],
) -> [u8; INDEX_LOCATOR_SIZE] {
    let mut raw = [0u8; INDEX_LOCATOR_SIZE];
    raw[..8].copy_from_slice(&INDEX_LOC_MAGIC);
    raw[8..16].copy_from_slice(&frame_len.to_le_bytes());
    raw[16..24].copy_from_slice(&frame_start.to_le_bytes());
    raw[24..28].copy_from_slice(&seq.to_le_bytes());
    raw[28..44].copy_from_slice(&archive_uuid);
    let mut crc_payload = Vec::with_capacity(36);
    crc_payload.extend_from_slice(&INDEX_LOC_MAGIC);
    crc_payload.extend_from_slice(&frame_len.to_le_bytes());
    crc_payload.extend_from_slice(&frame_start.to_le_bytes());
    crc_payload.extend_from_slice(&seq.to_le_bytes());
    crc_payload.extend_from_slice(&archive_uuid);
    let crc = crc32c(&crc_payload, 0);
    raw[44..48].copy_from_slice(&crc.to_le_bytes());
    raw
}

fn segment_metadata_for_count(
    current_segments: &[ArchiveSegment],
    final_segment_count: usize,
    repeated_segment_header_length: u64,
) -> Vec<TlvMap> {
    let mut metadata = Vec::new();
    for segment_index in 1..=final_segment_count {
        let header_len = if segment_index <= current_segments.len() {
            current_segments[segment_index - 1].physical_header_length
        } else if segment_index == 1 {
            0
        } else {
            repeated_segment_header_length
        };
        let mut seg = TlvMap::new();
        seg.insert("segment_index".into(), TlvValue::U64(segment_index as u64));
        seg.insert("physical_header_length".into(), TlvValue::U64(header_len));
        metadata.push(seg);
    }
    metadata
}

fn required_segment_count(
    current_segments: &[ArchiveSegment],
    part_size: Option<u64>,
    repeated_segment_header_length: u64,
    logical_append_bytes: u64,
) -> AmberResult<usize> {
    let Some(part_size) = part_size else {
        return Ok(1);
    };
    let current_last = current_segments
        .last()
        .ok_or_else(|| AmberError::Invalid("missing current segment".into()))?;
    let remaining_in_last = part_size.saturating_sub(current_last.physical_length());
    if logical_append_bytes <= remaining_in_last {
        return Ok(current_segments.len());
    }
    if logical_append_bytes > (part_size - repeated_segment_header_length) {
        return Err(AmberError::Invalid(
            "multipart segment size leaves no room for a complete index trailer".into(),
        ));
    }
    Ok(current_segments.len() + 1)
}

#[cfg(test)]
#[path = "tests/trailer.rs"]
mod tests;

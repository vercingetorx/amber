use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;

use blake3::Hasher;

use crate::codec::Codec;
use crate::constants::{RFLAG_CHUNK_TAG_PRESENT, RTYPE_CHUNK};
use crate::encryption::EncryptionContext;
use crate::error::AmberResult;
use crate::hashutil::blake3_32;
use crate::records::{RecordWriteTarget, build_chunk_header_ext, write_record};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkMeta {
    pub offset: u64,
    pub payload_offset: u64,
    pub payload_len: u64,
    pub uncompressed_len: u64,
    pub chunk_index: u64,
    pub blake3_32: [u8; 32],
}

pub struct ChunkEmitContext<'a, W: RecordWriteTarget> {
    pub fh: &'a mut W,
    pub encryptor: Option<&'a EncryptionContext>,
    pub symbol_size: usize,
    pub next_symbol_index: usize,
    pub symbol_bytes: BTreeMap<usize, Vec<u8>>,
    pub symbol_append:
        Box<dyn FnMut(&mut W, usize, u64, u64, usize, [u8; 32], &[u8]) -> AmberResult<()> + 'a>,
}

pub fn emit_file_chunks<W: RecordWriteTarget>(
    ctx: &mut ChunkEmitContext<'_, W>,
    entry_id: u64,
    fs_path: &std::path::Path,
    codec_id: u16,
    chunk_size: usize,
) -> AmberResult<(Vec<ChunkMeta>, [u8; 32])> {
    let mut chunks = Vec::new();
    let mut hasher = Hasher::new();
    let mut rf = File::open(fs_path)?;
    let codec = Codec::new(codec_id);
    let mut idx = 0u32;
    loop {
        let mut raw = vec![0u8; chunk_size];
        let read = rf.read(&mut raw)?;
        if read == 0 {
            break;
        }
        raw.truncate(read);
        hasher.update(&raw);
        let enc = codec.compress(&raw)?;
        let tag32 = blake3_32(&raw);
        write_chunk_payload(
            ctx,
            entry_id,
            idx,
            raw.len(),
            codec_id,
            &enc,
            &tag32,
            &mut chunks,
        )?;
        idx += 1;
    }
    let file_hash32: [u8; 32] = *hasher.finalize().as_bytes();
    Ok((chunks, file_hash32))
}

fn write_chunk_payload<W: RecordWriteTarget>(
    ctx: &mut ChunkEmitContext<'_, W>,
    entry_id: u64,
    idx: u32,
    raw_len: usize,
    codec_id: u16,
    enc: &[u8],
    tag32: &[u8; 32],
    chunks: &mut Vec<ChunkMeta>,
) -> AmberResult<()> {
    let hdr = build_chunk_header_ext(
        entry_id,
        idx,
        raw_len as u32,
        codec_id,
        tag32,
        &[0u8; 16],
        0,
    );
    let (record_offset, payload_offset, final_payload) = write_record(
        ctx.fh,
        RTYPE_CHUNK,
        RFLAG_CHUNK_TAG_PRESENT,
        &hdr,
        enc,
        ctx.encryptor,
    )?;
    chunks.push(ChunkMeta {
        offset: record_offset,
        payload_offset,
        payload_len: final_payload.len() as u64,
        uncompressed_len: raw_len as u64,
        chunk_index: idx as u64,
        blake3_32: *tag32,
    });
    let mut pos = 0usize;
    while pos < final_payload.len() {
        let end = (pos + ctx.symbol_size).min(final_payload.len());
        let seg = &final_payload[pos..end];
        let sym_index = ctx.next_symbol_index;
        ctx.next_symbol_index += 1;
        let seg_tag = blake3_32(seg);
        (ctx.symbol_append)(
            ctx.fh,
            sym_index,
            record_offset,
            payload_offset + pos as u64,
            seg.len(),
            seg_tag,
            seg,
        )?;
        ctx.symbol_bytes.insert(sym_index, seg.to_vec());
        pos = end;
    }
    Ok(())
}

impl<W: RecordWriteTarget> std::fmt::Debug for ChunkEmitContext<'_, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkEmitContext")
            .field("symbol_size", &self.symbol_size)
            .field("next_symbol_index", &self.next_symbol_index)
            .field("symbol_count", &self.symbol_bytes.len())
            .finish_non_exhaustive()
    }
}

use std::io::{Read, Seek, SeekFrom, Write};

use crate::constants::{REC_SYNC, RFLAG_HEADER_EXT};
use crate::crc32c::crc32c;
use crate::encryption::EncryptionContext;
use crate::error::{AmberError, AmberResult};

pub const RECORD_HEADER_SIZE: usize = 24;
pub const CHUNK_HEADER_EXT_SIZE: usize = 68;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordHeader {
    pub rtype: u8,
    pub rflags: u8,
    pub header_ext: Vec<u8>,
    pub payload_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub rtype: u8,
    pub rflags: u8,
    pub header_ext: Vec<u8>,
    pub payload: Vec<u8>,
}

pub trait RecordWriteTarget: Write + Seek {
    fn reserve_contiguous(&mut self, _length: u64) -> AmberResult<()> {
        Ok(())
    }
}

impl RecordWriteTarget for std::fs::File {}

impl RecordHeader {
    pub fn pack(&self) -> AmberResult<Vec<u8>> {
        let header_len = u16::try_from(self.header_ext.len())
            .map_err(|_| AmberError::Invalid("record header extension too large".into()))?;
        let mut fixed = [0u8; RECORD_HEADER_SIZE];
        fixed[0..4].copy_from_slice(&REC_SYNC);
        fixed[4] = self.rtype;
        fixed[5] = self.rflags | if header_len > 0 { RFLAG_HEADER_EXT } else { 0 };
        fixed[6..8].copy_from_slice(&header_len.to_le_bytes());
        fixed[8..16].copy_from_slice(&self.payload_len.to_le_bytes());
        fixed[16..20].copy_from_slice(&0u32.to_le_bytes());
        fixed[20..24].copy_from_slice(&0u32.to_le_bytes());
        let crc = crc32c(&fixed[..16], 0);
        let crc = crc32c(&self.header_ext, crc);
        fixed[16..20].copy_from_slice(&crc.to_le_bytes());

        let mut out = Vec::with_capacity(RECORD_HEADER_SIZE + self.header_ext.len());
        out.extend_from_slice(&fixed);
        out.extend_from_slice(&self.header_ext);
        Ok(out)
    }
}

pub fn write_record<W: RecordWriteTarget>(
    writer: &mut W,
    rtype: u8,
    rflags: u8,
    header_ext: &[u8],
    payload: &[u8],
    encryptor: Option<&EncryptionContext>,
) -> AmberResult<(u64, u64, Vec<u8>)> {
    let payload_len = payload.len() + encryptor.map_or(0, EncryptionContext::overhead);
    let header = RecordHeader {
        rtype,
        rflags,
        header_ext: header_ext.to_vec(),
        payload_len: payload_len as u64,
    };
    let header_bytes = header.pack()?;
    writer.reserve_contiguous((header_bytes.len() + payload_len) as u64)?;
    let off = writer.stream_position()?;
    let final_payload = match encryptor {
        Some(encryptor) => encryptor.encrypt(&header_bytes, payload, &off.to_le_bytes())?,
        None => payload.to_vec(),
    };
    writer.write_all(&header_bytes)?;
    let payload_offset = writer.stream_position()?;
    writer.write_all(&final_payload)?;
    Ok((off, payload_offset, final_payload))
}

pub fn read_exact_or_invalid<R: Read>(reader: &mut R, n: usize) -> AmberResult<Vec<u8>> {
    let mut buf = vec![0u8; n];
    match reader.read_exact(&mut buf) {
        Ok(()) => Ok(buf),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(AmberError::Invalid("Unexpected EOF".into()))
        }
        Err(err) => Err(err.into()),
    }
}

pub fn read_record_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    decryptor: Option<&EncryptionContext>,
) -> AmberResult<Record> {
    reader.seek(SeekFrom::Start(offset))?;
    read_record(reader, decryptor)
}

pub fn read_record<R: Read + Seek>(
    reader: &mut R,
    decryptor: Option<&EncryptionContext>,
) -> AmberResult<Record> {
    let rec_off = reader.stream_position()?;
    let fixed = read_exact_or_invalid(reader, RECORD_HEADER_SIZE)?;
    if fixed[0..4] != REC_SYNC {
        return Err(AmberError::Invalid("Bad record sync".into()));
    }
    let rtype = fixed[4];
    let rflags = fixed[5];
    let header_len = u16::from_le_bytes([fixed[6], fixed[7]]) as usize;
    let payload_len = u64::from_le_bytes(fixed[8..16].try_into().unwrap());
    let hdr_crc = u32::from_le_bytes(fixed[16..20].try_into().unwrap());
    let header_ext = if header_len == 0 {
        Vec::new()
    } else {
        read_exact_or_invalid(reader, header_len)?
    };
    let calc_crc = crc32c(&fixed[..16], 0);
    let calc_crc = crc32c(&header_ext, calc_crc);
    if calc_crc != hdr_crc {
        return Err(AmberError::Invalid("Record header CRC32C mismatch".into()));
    }
    let payload = read_exact_or_invalid(
        reader,
        usize::try_from(payload_len)
            .map_err(|_| AmberError::Invalid("record payload too large for platform".into()))?,
    )?;
    let payload = match decryptor {
        Some(decryptor) => {
            let mut header_bytes = fixed.clone();
            header_bytes.extend_from_slice(&header_ext);
            decryptor.decrypt(&header_bytes, &payload, &rec_off.to_le_bytes())?
        }
        None => payload,
    };
    Ok(Record {
        rtype,
        rflags,
        header_ext,
        payload,
    })
}

pub fn build_chunk_header_ext(
    entry_id: u64,
    chunk_index: u32,
    uncompressed_len: u32,
    codec_id: u16,
    tag32: &[u8; 32],
    aux16: &[u8; 16],
    flags: u16,
) -> [u8; CHUNK_HEADER_EXT_SIZE] {
    let mut out = [0u8; CHUNK_HEADER_EXT_SIZE];
    let mut pos = 0usize;
    out[pos..pos + 8].copy_from_slice(&entry_id.to_le_bytes());
    pos += 8;
    out[pos..pos + 4].copy_from_slice(&chunk_index.to_le_bytes());
    pos += 4;
    out[pos..pos + 4].copy_from_slice(&uncompressed_len.to_le_bytes());
    pos += 4;
    out[pos..pos + 2].copy_from_slice(&codec_id.to_le_bytes());
    pos += 2;
    out[pos..pos + 2].copy_from_slice(&flags.to_le_bytes());
    pos += 2;
    out[pos..pos + 32].copy_from_slice(tag32);
    pos += 32;
    out[pos..pos + 16].copy_from_slice(aux16);
    out
}

pub fn parse_chunk_header_ext(
    header_ext: &[u8],
) -> AmberResult<(u64, u32, u32, u16, u16, [u8; 32], [u8; 16])> {
    if header_ext.len() < CHUNK_HEADER_EXT_SIZE {
        return Err(AmberError::Invalid("chunk header_ext too short".into()));
    }
    let mut pos = 0usize;
    let entry_id = u64::from_le_bytes(header_ext[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let chunk_index = u32::from_le_bytes(header_ext[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let uncompressed_len = u32::from_le_bytes(header_ext[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let codec_id = u16::from_le_bytes(header_ext[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let flags = u16::from_le_bytes(header_ext[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let mut tag32 = [0u8; 32];
    tag32.copy_from_slice(&header_ext[pos..pos + 32]);
    pos += 32;
    let mut aux16 = [0u8; 16];
    aux16.copy_from_slice(&header_ext[pos..pos + 16]);
    Ok((
        entry_id,
        chunk_index,
        uncompressed_len,
        codec_id,
        flags,
        tag32,
        aux16,
    ))
}

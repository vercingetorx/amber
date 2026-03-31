use std::io::{Read, Seek, SeekFrom};

use crate::constants::{KDF_NONE, SUPERBLOCK_MAGIC, VERSION_MAJOR, VERSION_MINOR};
use crate::crc32c::crc32c;
use crate::error::{AmberError, AmberResult};

pub const SUPERBLOCK_SIZE: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Superblock {
    pub version_major: u16,
    pub version_minor: u16,
    pub flags: u32,
    pub uuid: [u8; 16],
    pub created_sec: u64,
    pub created_nanos: u32,
    pub default_chunk_size: u32,
    pub default_codec: u32,
    pub multipart_part_size: u64,
    pub kdf_id: u16,
    pub kdf_salt: [u8; 16],
    pub argon_memory_cost: u32,
    pub argon_time_cost: u32,
    pub argon_parallelism: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuperblockEncryptionParams {
    pub kdf_id: u16,
    pub salt: [u8; 16],
    pub argon_mem: u32,
    pub argon_time: u32,
    pub argon_lanes: u32,
}

pub fn pack_superblock(
    flags: u32,
    archive_uuid: [u8; 16],
    created_sec: u64,
    created_nanos: u32,
    default_chunk_size: u32,
    default_codec: u32,
    multipart_part_size: Option<u64>,
    enc_params: Option<&SuperblockEncryptionParams>,
) -> [u8; SUPERBLOCK_SIZE] {
    let (kdf_id, salt, argon_mem, argon_time, argon_lanes) = match enc_params {
        Some(params) => (
            params.kdf_id,
            params.salt,
            params.argon_mem,
            params.argon_time,
            params.argon_lanes,
        ),
        None => (KDF_NONE, [0u8; 16], 0, 0, 0),
    };

    let mut raw = [0u8; SUPERBLOCK_SIZE];
    let mut pos = 0usize;

    write_bytes(&mut raw, &mut pos, &SUPERBLOCK_MAGIC);
    write_u16(&mut raw, &mut pos, VERSION_MAJOR);
    write_u16(&mut raw, &mut pos, VERSION_MINOR);
    write_u32(&mut raw, &mut pos, flags);
    write_bytes(&mut raw, &mut pos, &archive_uuid);
    write_u64(&mut raw, &mut pos, created_sec);
    write_u32(&mut raw, &mut pos, created_nanos);
    write_u32(&mut raw, &mut pos, default_chunk_size);
    write_u32(&mut raw, &mut pos, default_codec);
    write_u16(&mut raw, &mut pos, 0);
    write_u16(&mut raw, &mut pos, kdf_id);
    write_bytes(&mut raw, &mut pos, &salt);
    write_u32(&mut raw, &mut pos, argon_mem);
    write_u32(&mut raw, &mut pos, argon_time);
    write_u32(&mut raw, &mut pos, argon_lanes);
    write_u64(&mut raw, &mut pos, multipart_part_size.unwrap_or(0));
    write_u32(&mut raw, &mut pos, 0);
    write_bytes(&mut raw, &mut pos, &[0u8; 28]);
    write_u32(&mut raw, &mut pos, 0);

    let crc = crc32c(&raw[..SUPERBLOCK_SIZE - 4], 0);
    raw[SUPERBLOCK_SIZE - 4..].copy_from_slice(&crc.to_le_bytes());
    raw
}

pub fn read_superblock<R: Read + Seek>(reader: &mut R) -> AmberResult<Superblock> {
    reader.seek(SeekFrom::Start(0))?;
    let mut raw = [0u8; SUPERBLOCK_SIZE];
    match reader.read_exact(&mut raw) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(AmberError::Invalid("Superblock too short".into()));
        }
        Err(err) => return Err(err.into()),
    }

    let mut pos = 0usize;
    let magic = read_array::<8>(&raw, &mut pos);
    let version_major = read_u16(&raw, &mut pos);
    let version_minor = read_u16(&raw, &mut pos);
    let flags = read_u32(&raw, &mut pos);
    let uuid = read_array::<16>(&raw, &mut pos);
    let created_sec = read_u64(&raw, &mut pos);
    let created_nanos = read_u32(&raw, &mut pos);
    let default_chunk_size = read_u32(&raw, &mut pos);
    let default_codec = read_u32(&raw, &mut pos);
    let _reserved_u16 = read_u16(&raw, &mut pos);
    let kdf_id = read_u16(&raw, &mut pos);
    let kdf_salt = read_array::<16>(&raw, &mut pos);
    let argon_memory_cost = read_u32(&raw, &mut pos);
    let argon_time_cost = read_u32(&raw, &mut pos);
    let argon_parallelism = read_u32(&raw, &mut pos);
    let multipart_part_size = read_u64(&raw, &mut pos);
    let _reserved_u32 = read_u32(&raw, &mut pos);
    let _reserved_28 = read_array::<28>(&raw, &mut pos);
    let hdr_crc = read_u32(&raw, &mut pos);

    if magic != SUPERBLOCK_MAGIC {
        return Err(AmberError::Invalid("Bad superblock magic".into()));
    }
    if version_major != VERSION_MAJOR {
        return Err(AmberError::Invalid(format!(
            "Unsupported archive version {}.{}; expected major {}",
            version_major, version_minor, VERSION_MAJOR
        )));
    }
    if crc32c(&raw[..SUPERBLOCK_SIZE - 4], 0) != hdr_crc {
        return Err(AmberError::Invalid("Superblock CRC mismatch".into()));
    }

    Ok(Superblock {
        version_major,
        version_minor,
        flags,
        uuid,
        created_sec,
        created_nanos,
        default_chunk_size,
        default_codec,
        multipart_part_size,
        kdf_id,
        kdf_salt,
        argon_memory_cost,
        argon_time_cost,
        argon_parallelism,
    })
}

fn write_bytes(dst: &mut [u8], pos: &mut usize, bytes: &[u8]) {
    let end = *pos + bytes.len();
    dst[*pos..end].copy_from_slice(bytes);
    *pos = end;
}

fn write_u16(dst: &mut [u8], pos: &mut usize, value: u16) {
    write_bytes(dst, pos, &value.to_le_bytes());
}

fn write_u32(dst: &mut [u8], pos: &mut usize, value: u32) {
    write_bytes(dst, pos, &value.to_le_bytes());
}

fn write_u64(dst: &mut [u8], pos: &mut usize, value: u64) {
    write_bytes(dst, pos, &value.to_le_bytes());
}

fn read_array<const N: usize>(src: &[u8], pos: &mut usize) -> [u8; N] {
    let end = *pos + N;
    let mut out = [0u8; N];
    out.copy_from_slice(&src[*pos..end]);
    *pos = end;
    out
}

fn read_u16(src: &[u8], pos: &mut usize) -> u16 {
    u16::from_le_bytes(read_array(src, pos))
}

fn read_u32(src: &[u8], pos: &mut usize) -> u32 {
    u32::from_le_bytes(read_array(src, pos))
}

fn read_u64(src: &[u8], pos: &mut usize) -> u64 {
    u64::from_le_bytes(read_array(src, pos))
}

#[cfg(test)]
#[path = "tests/superblock.rs"]
mod tests;

use crate::error::AmberResult;
use crate::tlv::{tlv, varint_encode};

pub struct EntryBeginPayload<'a> {
    pub entry_id: u64,
    pub kind: u64,
    pub path: &'a str,
    pub mode: Option<u64>,
    pub mtime_sec: Option<u64>,
    pub mtime_nsec: Option<u64>,
    pub atime_sec: Option<u64>,
    pub atime_nsec: Option<u64>,
    pub size: Option<u64>,
    pub file_codec: Option<u64>,
    pub chunk_size: Option<u64>,
    pub symlink_target: Option<&'a str>,
}

pub fn build_entry_begin_payload(spec: EntryBeginPayload<'_>) -> AmberResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend(tlv(1, &varint_encode(spec.entry_id))?);
    out.extend(tlv(2, &varint_encode(spec.kind))?);
    out.extend(tlv(3, spec.path.as_bytes())?);
    if let Some(mode) = spec.mode {
        out.extend(tlv(4, &varint_encode(mode))?);
    }
    if let Some(mtime_sec) = spec.mtime_sec {
        out.extend(tlv(
            5,
            &[
                varint_encode(mtime_sec),
                varint_encode(spec.mtime_nsec.unwrap_or(0)),
            ]
            .concat(),
        )?);
    }
    if let Some(atime_sec) = spec.atime_sec {
        out.extend(tlv(
            6,
            &[
                varint_encode(atime_sec),
                varint_encode(spec.atime_nsec.unwrap_or(0)),
            ]
            .concat(),
        )?);
    }
    if let Some(size) = spec.size {
        out.extend(tlv(7, &varint_encode(size))?);
    }
    if let Some(file_codec) = spec.file_codec {
        out.extend(tlv(8, &varint_encode(file_codec))?);
    }
    if let Some(chunk_size) = spec.chunk_size {
        out.extend(tlv(9, &varint_encode(chunk_size))?);
    }
    if spec.kind == 2 {
        if let Some(target) = spec.symlink_target {
            out.extend(tlv(10, target.as_bytes())?);
        }
    }
    Ok(out)
}

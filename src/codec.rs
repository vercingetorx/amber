use std::io::{Read, Write};

use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use zstd::stream::{read::Decoder as ZstdDecoder, write::Encoder as ZstdEncoder};

use crate::constants::{CODEC_MDS_PARITY, CODEC_DEFLATE, CODEC_NONE, CODEC_ZSTD};
use crate::error::{AmberError, AmberResult};

#[derive(Clone, Debug)]
pub struct Codec {
    pub codec_id: u16,
}

impl Codec {
    pub fn new(codec_id: u16) -> Self {
        Self { codec_id }
    }

    pub fn compress(&self, data: &[u8]) -> AmberResult<Vec<u8>> {
        match self.codec_id {
            CODEC_NONE | CODEC_MDS_PARITY => Ok(data.to_vec()),
            CODEC_DEFLATE => {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(6));
                encoder.write_all(data)?;
                Ok(encoder.finish()?)
            }
            CODEC_ZSTD => {
                let mut encoder = ZstdEncoder::new(Vec::new(), 3).map_err(|err| {
                    AmberError::Invalid(format!("zstd compression failed: {err}"))
                })?;
                encoder.write_all(data).map_err(|err| {
                    AmberError::Invalid(format!("zstd compression failed: {err}"))
                })?;
                encoder
                    .finish()
                    .map_err(|err| AmberError::Invalid(format!("zstd compression failed: {err}")))
            }
            other => Err(AmberError::Invalid(format!(
                "unsupported codec id: {other}"
            ))),
        }
    }

    pub fn decompress(&self, data: &[u8], max_output_size: Option<usize>) -> AmberResult<Vec<u8>> {
        match self.codec_id {
            CODEC_NONE | CODEC_MDS_PARITY => {
                if let Some(limit) = max_output_size
                    && data.len() > limit
                {
                    return Err(AmberError::Invalid(
                        "payload exceeds configured decompression limit".into(),
                    ));
                }
                Ok(data.to_vec())
            }
            CODEC_DEFLATE => decompress_deflate_bounded(data, max_output_size),
            CODEC_ZSTD => decompress_zstd_bounded(data, max_output_size),
            other => Err(AmberError::Invalid(format!(
                "unsupported codec id: {other}"
            ))),
        }
    }
}

pub fn compressed_len_upper_bound(codec_id: u16, input_len: u64) -> AmberResult<u64> {
    match codec_id {
        CODEC_NONE | CODEC_MDS_PARITY => Ok(input_len),
        CODEC_DEFLATE => deflate_compress_bound(input_len),
        CODEC_ZSTD => zstd_compress_bound(input_len),
        other => Err(AmberError::Invalid(format!(
            "unsupported codec id: {other}"
        ))),
    }
}

fn deflate_compress_bound(input_len: u64) -> AmberResult<u64> {
    input_len
        .checked_add(input_len >> 12)
        .and_then(|value| value.checked_add(input_len >> 14))
        .and_then(|value| value.checked_add(input_len >> 25))
        .and_then(|value| value.checked_add(13))
        .ok_or_else(|| AmberError::Invalid("deflate compressed-size bound overflow".into()))
}

fn zstd_compress_bound(input_len: u64) -> AmberResult<u64> {
    let input_len = usize::try_from(input_len)
        .map_err(|_| AmberError::Invalid("zstd input chunk length exceeds usize".into()))?;
    u64::try_from(zstd::zstd_safe::compress_bound(input_len))
        .map_err(|_| AmberError::Invalid("zstd compressed-size bound overflow".into()))
}

fn decompress_deflate_bounded(data: &[u8], max_output_size: Option<usize>) -> AmberResult<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = decoder.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..read]);
        if let Some(limit) = max_output_size
            && out.len() > limit
        {
            return Err(AmberError::Invalid(
                "deflate payload exceeds configured decompression limit".into(),
            ));
        }
    }
    Ok(out)
}

fn decompress_zstd_bounded(data: &[u8], max_output_size: Option<usize>) -> AmberResult<Vec<u8>> {
    let mut decoder = ZstdDecoder::new(data)
        .map_err(|err| AmberError::Invalid(format!("zstd decompression failed: {err}")))?;
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = decoder
            .read(&mut chunk)
            .map_err(|err| AmberError::Invalid(format!("zstd decompression failed: {err}")))?;
        if read == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..read]);
        if let Some(limit) = max_output_size
            && out.len() > limit
        {
            return Err(AmberError::Invalid(
                "zstd payload exceeds configured decompression limit".into(),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "tests/codec.rs"]
mod tests;

use getrandom::fill;

pub const SUPERBLOCK_MAGIC: [u8; 8] = *b"AMBERAR\0";
pub const INDEX_FRAME_MAGIC: [u8; 8] = *b"AMBRIDX\0";
pub const INDEX_LOC_MAGIC: [u8; 8] = *b"AMBRLOC\0";

pub const VERSION_MAJOR: u16 = 3;
pub const VERSION_MINOR: u16 = 0;

pub const FLAG_ENCRYPTED: u32 = 1 << 0;
pub const FLAG_ECC_PRESENT: u32 = 1 << 1;
pub const FLAG_INDEX_COMPRESSED: u32 = 1 << 2;
pub const FLAG_CHUNK_COMPRESS_DEFAULT: u32 = 1 << 3;

pub const KDF_NONE: u16 = 0;
pub const KDF_ARGON2ID_V2: u16 = 2;

pub const REC_SYNC: [u8; 4] = [0xD2, 0x53, 0x54, 0x52];

pub const RTYPE_ENTRY_BEGIN: u8 = 0;
pub const RTYPE_CHUNK: u8 = 1;
pub const RTYPE_ENTRY_END: u8 = 2;
pub const RTYPE_PADDING: u8 = 3;
pub const RTYPE_ANCHOR: u8 = 4;

pub const RFLAG_HEADER_EXT: u8 = 1 << 0;
pub const RFLAG_CHUNK_TAG_PRESENT: u8 = 1 << 1;
pub const RFLAG_PARITY_RECORD: u8 = 1 << 2;

pub const CODEC_NONE: u16 = 0;
pub const CODEC_DEFLATE: u16 = 1;
pub const CODEC_ZSTD: u16 = 2;
pub const CODEC_AMCF_PARITY: u16 = 0x8201;

pub const DEFAULT_CHUNK_SIZE: u32 = 262_144;
pub const DEFAULT_CODEC_ID: u16 = CODEC_NONE;

pub fn new_uuid_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    fill(&mut out).expect("system RNG unavailable for UUID generation");
    out[6] = (out[6] & 0x0F) | 0x40;
    out[8] = (out[8] & 0x3F) | 0x80;
    out
}

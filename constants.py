import uuid


# Magic and version
SUPERBLOCK_MAGIC = b"AMBERAR\x00"   # 8 bytes: "AMBERAR\0"
INDEX_FRAME_MAGIC = b"AMBRIDX\x00"  # 8 bytes: "AMBRIDX\0"
INDEX_LOC_MAGIC = b"AMBRLOC\x00"    # 8 bytes: "AMBRLOC\0"

VERSION_MAJOR = 1
VERSION_MINOR = 0

# Superblock flags
FLAG_ENCRYPTED = 1 << 0
FLAG_ECC_PRESENT = 1 << 1
FLAG_INDEX_COMPRESSED = 1 << 2
FLAG_CHUNK_COMPRESS_DEFAULT = 1 << 3


# Record constants
REC_SYNC = bytes([0xD2, 0x53, 0x54, 0x52])  # 0xD2 'S' 'T' 'R'

RTYPE_ENTRY_BEGIN = 0
RTYPE_CHUNK = 1
RTYPE_ENTRY_END = 2
RTYPE_PADDING = 3
RTYPE_ANCHOR = 4

# Record flags
RFLAG_HEADER_EXT = 1 << 0
RFLAG_CHUNK_TAG_PRESENT = 1 << 1
RFLAG_PARITY_RECORD = 1 << 2


# Codec IDs (POC mapping; 0=none, 1=deflate/zlib, 2=zstd)
CODEC_NONE = 0
CODEC_DEFLATE = 1
CODEC_ZSTD = 2

# ECC parity codec identifiers (non-standard range)
CODEC_LRP_PARITY = 0x8101
CODEC_RX_PARITY = 0x8201


DEFAULT_CHUNK_SIZE = 1_048_576  # 1 MiB
DEFAULT_CODEC_ID = CODEC_DEFLATE


def new_uuid_bytes() -> bytes:
    return uuid.uuid4().bytes

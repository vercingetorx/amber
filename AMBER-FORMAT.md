Amber .amber Archive — v0 Design

Overview

- Purpose: a minimal, modern archive container focused on long-term safety against bit rot, with built-in integrity checks and an optional, first-class error-correction layer. Supports files and directories with sane metadata and optional whole-archive encryption.
- Extension: .amber
- Scope: create archives and safely append new entries and/or parity later without rewriting existing payload. Original payload remains immutable; a fresh trailer reflects appended content.
- Portability: binary format with clear endianness and versioning; avoids OS-specific assumptions; uses UTF-8 for paths.

Goals

- Safety first: strong per-chunk integrity, whole-archive verifiability, and space for error-correction parity.
- Simplicity: fewer modes, explicit decisions, small set of codecs and ciphers.
- Streaming: can write sequentially without knowing sizes in advance; finalize with an index at the end.
- Random access: central index records chunk offsets for fast listing and extraction.
- Future-proofing: versioned structures, reserved fields, and feature flags; tolerate unknown flags while preserving data.

Non-Goals (for v0)

- In-place update/overwrite of existing archives.
- Deduplication and content-addressable store (may come later, but not required for v0).
- Delta compression.
- Per-file encryption modes (v0 supports either no encryption or whole-archive encryption).

Data Model

- Entry kinds:
  - file: regular file with byte content.
  - dir: directory marker (no content).
  - symlink: path target stored as UTF-8 text.
  - (future) hardlink: reference to another file entry by id.

- Metadata (common):
  - name: UTF-8 normalized path with forward slashes, no absolute paths, no .. components; max 1024 bytes encoded (configurable in future).
  - mode: POSIX-like permissions (u16). Optional.
  - uid/gid: optional u32s for POSIX; omitted on platforms where not meaningful.
  - timestamps: mtime required; ctime/atime optional; 64-bit seconds since Unix epoch + 32-bit nanoseconds.
  - xattrs: optional key/value bag (UTF-8 keys; values as bytes), constrained by size limits.

- File content:
  - Split into fixed-size chunks (default 1 MiB uncompressed; configurable per-archive). Last chunk may be smaller.
  - Each chunk may be compressed (default deflate/zlib in POC) and always has integrity protection.

Encoding Conventions

- Endianness: little endian for all fixed-width integers.
- Variable-length integers: unsigned LEB128 (uLEB128) for lengths, indexes, and counts in flexible structures (saves space without 64-bit bloat).
- Cryptographic hash: BLAKE2s-256; stored as 16-byte truncated digests where space is critical, and 32-byte full digests for top-level commitments (Merkle roots, index hash). Truncation length is recorded where applicable.
- Checksums: CRC32C for lightweight header integrity; cryptographic BLAKE2s where tamper/rot detection matters.

On-Disk Layout (high-level)

  [Superblock (public header)]
  [Data Section: a sequence of Records]
  [Index A (trailer)]
  [Index B (redundant copy)]

- Superblock: fixed-size structure at offset 0 containing magic, version, flags, archive UUID, creation time, and key-derivation params if encrypted. Everything after the superblock may be encrypted as a single domain (see Encryption).
- Records: self-delimiting blocks (with a small header and CRC32C) that carry entry declarations, chunk payloads, and other future-typed data. Record headers enable stream scanning and resync.
- Index: written at finalize; includes a complete manifest and a chunk map per file. Two copies are written back-to-back at the end to mitigate single-point tail damage. Each copy carries:
  - index encoding (TLV),
  - optional compression (deflate/zlib in POC),
  - BLAKE2s hash of the uncompressed index payload,
  - Merkle root over all chunk digests (global commitment),
  - locator footer with sizes and a short magic for backward scanning.

Superblock (Public Header)

Fixed 128 bytes at offset 0 (sizes chosen for alignment and growth; some fields reserved):

- magic[8]: ASCII "AMBERAR\x00"
- version_major u16 = 1
- version_minor u16 = 0
- flags u32:
  - bit 0: encrypted (everything after superblock is encrypted)
  - bit 1: error-correction present (see ECC Groups)
  - bit 2: index compressed
  - bit 3: chunk compression default enabled
  - others: reserved
- archive_uuid[16]: random UUID v4
- created_unix_sec u64; created_unix_nanos u32
- default_chunk_size u32 (bytes), default 1_048_576
- default_codec u16 (0=none, 1=deflate/zlib, 2=zstd) — POC uses 1=deflate/zlib
- kdf_params (if encrypted):
  - kdf_id u16 (0=none, 1=Argon2id)
  - kdf_salt[16]
  - argon_mem_cost_kib u32 (fixed to 262144 in current implementation)
  - argon_time_cost u32 (fixed to 3)
  - argon_lanes u32 (fixed to 4)
  - reserved u32 x3 (currently zero)
- reserved[?]: pad to 124 bytes
- header_crc32c u32 over first 124 bytes

Record Stream (Data Section)

Records are written sequentially after the superblock. Each starts with a small header enabling a reader to resynchronize after local damage.

Record Header (fixed 24 bytes):

- sync[4]: 0xD2 0x53 0x54 0x52 ("\xD2STR") — a non-ASCII lead byte plus ASCII helps mis-detection
- rtype u8: 0=EntryBegin, 1=Chunk, 2=EntryEnd, 3=Padding, 4=Anchor, 5=Reserved
- rflags u8: bit 0: header_ext_present; bit 1: payload_bla_ke3_16_present; others reserved
- header_len u16: bytes after this header up to payload (allows variable header extensions)
- payload_len u64: length of payload bytes following the header (ciphertext length if encrypted)
- header_crc32c u32: CRC of the entire header including extensions

Record Types

- EntryBegin (rtype=0): logical start of an entry. Payload is a TLV map with:
  - entry_id u64: monotonically increasing id assigned during write
  - kind u8: 0=file, 1=dir, 2=symlink
  - path utf8 string (normalized)
  - mode u16 (optional)
  - uid u32, gid u32 (optional)
  - mtime {sec u64, nsec u32}
  - atime/ctime optional
  - size u64 (for files; may be 0 if unknown at start; filled in Index)
  - xattrs map<string, bstr> (optional)
  - file_codec u16 (optional override; else default_codec)
  - chunk_size u32 (optional override; else default_chunk_size)

- Chunk (rtype=1): carries bytes for a file entry and ECC parity.
  - Header extension (POC fixed struct): `<QIIHH16s16s>`
    - entry_id u64 (0 for parity symbols)
    - chunk_index u32 (data: per-file chunk index; LRP parity: stripe index; RX parity: seed_id)
    - uncompressed_len u32 (data: raw chunk bytes; parity: symbol_size)
    - codec_id u16 (0=none, 1=deflate, 2=zstd, 0x8101=LRP parity, 0x8201=RX parity)
    - flags u16 (reserved, 0)
    - tag16 bstr[16] (BLAKE2s‑128 over raw chunk bytes for data; over parity payload for parity)
    - aux16 bstr[16] (RX parity only: seed_base; zero otherwise)
  - rflags: bit 1 set when tag16 present; bit 2 set when this is a parity record.
  - Payload: either raw or compressed chunk; for parity, payload is the parity symbol bytes. If archive is encrypted, payload is AEAD ciphertext.

- EntryEnd (rtype=2): closes an entry. Header extension contains entry_id u64 and total_chunk_count u32. No payload.

- Padding (rtype=3): alignment padding; payload is zero bytes or random bytes (if encrypted, ciphertext looks random anyway). Reader skips.

- Anchor (rtype=4): periodic recovery snapshot. Writers emit anchors at intervals (default ~64 MiB of new data symbols) and once just before the trailer. Payload is TLV with:
  - version u16 = 1
  - symbol_size u32
  - merkle_root bstr[32]
  - seed_base bstr[16] (optional; present if RX parity exists)
  - symbols: array (up to last 64 symbols) of {symbol_index u32, offset u64, record_offset u64 (optional), length u32, tag16 bstr[16], is_parity bool, seed_base bstr[16] (optional)}

Index (Trailer)

Two back-to-back copies are written at finalize for redundancy.

- Index Payload (logical content, before compression/encryption):
  - encoding: TLV structure with fields:
    - version: {major u16, minor u16}
    - archive_uuid: bstr[16]
    - writer_info: string
    - default_chunk_size u32; default_codec u16
    - entries: array of entry objects, each:
      - entry_id u64, kind u8, path string, mode/uid/gid optional
      - mtime/ctime/atime
      - size u64 (for files)
      - symlink_target string (for symlink)
      - file_codec u16 optional; chunk_size u32 optional
      - chunks: array of chunk descriptors for files:
        - {offset u64, payload_len u32, uncompressed_len u32, chunk_index u32, blake2s_16 bstr[16]}
      - file_blake2s_32 bstr[32] (BLAKE2s over uncompressed file bytes)
    - archive_merkle_root bstr[32] computed over all chunk blake2s_16 digests in file order using a binary Merkle (documented below)
    - ecc_groups: array of ECC group descriptors. Each group contains:
      - group_id u32; symbol_size u32; lrp {k u16, p u16}
      - rx {seed_base bstr[16], epsilon_ppm u32, parity: array of {symbol_index u32, seed_id u32, offset u64, length u32, tag16 bstr[16], seed_base bstr[16]}}
      - symbols: array of {symbol_index u32, offset u64, record_offset u64, length u32, tag16 bstr[16], stripe_index i32, is_parity bool, seed_base bstr[16] (optional)}
      - stripes: array of {stripe_index u32, data_symbols: array<u32>, parity_symbol u32}
    - extras: map<string, any> (vendor/reserved)

- Index Frame (as stored on disk; each copy):
- frame_magic[8]: "AMBRIDX\x00"
  - frame_flags u32: bit 0: compressed; bit 1: encrypted (if whole-archive encryption this will also be true implicitly); others reserved
  - uncompressed_len u64
- index_hash bstr[32]: BLAKE2s of uncompressed TLV payload
  - merkle_root bstr[32]: repeated for convenience and early verification
- payload: either raw TLV, or zlib-compressed TLV
  - frame_crc32c u32: CRC over header and payload (excluding this field)

- Locator (immediately after each Index Frame):
- loc_magic[8]: "AMBRLOC\x00"
  - frame_len u64: bytes of the preceding Index Frame
  - frame_off u64: absolute file offset where the Index Frame begins
  - copy_seq u32: 0 for Index A, 1 for Index B
  - archive_uuid[16]
  - locator_crc32c u32: CRC32C over loc_magic || frame_len || frame_off || copy_seq || archive_uuid

Readers discover the trailer by scanning backwards for loc_magic, validate the locator CRC and archive_uuid, then jump to frame_off.

Merkle Construction (archive_merkle_root)

- Leaves: the 16-byte blake2s truncated digests of each chunk (as stored in Chunk headers) left-padded to 32 bytes by zero-extending to 32 (or expand to the full BLAKE2s-256 of the preimage). Simpler v0 approach: compute a fresh BLAKE2s-256 for each leaf from the stored 16 bytes (domain-separated) to produce 32-byte leaves.
- Inner nodes: hash(left || right) using BLAKE2s-256 with a domain separator label (e.g., "SS_MERKLE_NODE").
- Odd leaf: promoted (copy up) or hash with a zero node; we choose promote.
- Root stored in Index and Index Frame header.

Encryption (Whole-Archive)

- Modes: none (default) or full. If enabled, everything after the Superblock is encrypted, including chunk, parity, and anchor Records and both Index copies. The Superblock remains public to carry KDF params.
- Cipher (POC): XChaCha20-Poly1305 (192-bit nonce) via PyCryptodomex.
- KDF: Argon2id with fixed parameters (time_cost=3, memory_cost=262144 KiB, lanes=4) recorded in the Superblock to derive a 32-byte key. Salt is 16 bytes random. Password-based only for v0; keyfile support may come later.
- Nonce: Derived per record via HMAC(key, "AMBER_REC_NONCE" || record_offset) to produce a deterministic 24-byte XChaCha nonce.
- Integrity: AEAD authenticates ciphertext and prevents undetected modification; per-chunk blake2s_16 is computed over uncompressed plaintext chunk bytes and stored inside the encrypted header for post-decrypt validation. ECC operates over storage bytes (post-compression and, if enabled, post-encryption).
- Metadata privacy: entry names and the index are encrypted; nothing leaks except archive size and Superblock.

Integrity (Detection)

- Per-record header CRC32C to quickly detect header damage and resync.
- Per-chunk blake2s_16 (truncated) for localized detection and targeted repair.
- Per-file blake2s_32 for end-to-end verification of file contents.
- Archive-level Merkle root for holistic verification without reading all data (with a sparse proof format in a future version).
- Index hashes and frame CRCs to protect the trailer.

Error Correction (AMSEC)

- The .amber format includes a first-class, multi-scale ECC regime called AMSEC (Adaptive Multi‑Scale Error Correction). See docs/AMBER-ECC.md:1 for the full design.
- High level:
  - LRP (Local Repair Parity): optional small‑stripe XOR parity for fast single‑symbol repairs with low overhead.
  - RX (Raptor‑style deterministic rateless parity): GF(256) random linear parity over large windows, rateless and appendable.
- ECC metadata lives in Index.ecc_groups with descriptors that define windows, symbol size, interleaving, and parity references. Parity is stored as special Chunk records (codec_id 0x8101 for LRP, 0x8201 for RX).
- ECC operates over storage bytes (post‑compression, post‑encryption) and can be appended later without rewriting the archive.

Compression

- Default: deflate/zlib (codec_id=1). Per-file override via EntryBegin or per-chunk codec in Chunk headers. The index has its own compression flag independent of chunk compression. Zstd (codec_id=2) is supported when a zstd implementation is available; if not, attempting to write/read zstd chunks is an error.
- Rationale: zlib keeps dependencies minimal while still providing broadly-compatible compression.

Streaming and Random Access

- Writers can stream: write EntryBegin, then a sequence of Chunk records, then EntryEnd for each path. When finished, write the Index copies.
- Readers without an index can still scan and list/extract sequentially by following Records (useful for partial recovery), but random access relies on the Index for offsets.

Limits and Sizes

- Archive size: up to 2^64−1 bytes.
- Path length: up to 1024 bytes UTF-8 (v0 guideline; bounded by practical implementation limits).
- Chunk sizes: typical 1 MiB (default) to 8 MiB; very small chunks increase overhead; very large chunks reduce ECC granularity.
- Maximum entries: practical limit of u64; implementations may constrain for memory.
- Index safety cap (implementation): readers reject index frames whose declared uncompressed length exceeds a default cap (128 MiB) to avoid decompression bombs and unbounded memory.
- Bounds-checked decode (implementation): readers apply limits to entries, total chunks, symbols, stripes, and RX parity counts to ensure bounded memory and robust parsing.

Compatibility and Evolution

- Versioning: major increments indicate breaking structural changes; minor increments add fields/flags in a backward-compatible manner.
- Unknown rtype or flags: skip if length is known and header validates.
- Extras: reserved tags/padding in headers allow vendor or future fields.

Security Considerations

- Path normalization: reject absolute paths and any component equal to "." or "..". Store normalized UTF-8; disallow NUL.
- Symlinks: do not resolve during archive creation; store as-is; extraction policy left to caller.
- Zip-slip protection: extraction must prevent traversal outside the target directory.
- Authentication: if encrypted, all Records are AEAD-protected and tamper-evident. If not encrypted, integrity relies on BLAKE2s and CRCs.

MIME and Identification

- File extension: .amber
- Suggested MIME: application/x-amber
- Magic bytes: Superblock magic "AMBERAR\x00" at offset 0; backward scans use "AMBRLOC\x00" and "AMBRIDX\x00" markers.

POC Implementation Plan (Python)

- Dependencies (baseline, pure-Python friendly where possible):
  - hashlib (blake2s) for hashing
  - zlib for compression
  - pickle for index encoding
- PyCryptodomex (XChaCha20-Poly1305) only when encryption is enabled
  - Built-in CRC32C implementation

- Writer (ArchiveWriter):
  - init(superblock params)
  - add_file(path, stream, metadata, codec=None, chunk_size=None)
  - add_dir(path, metadata)
  - add_symlink(path, target)
  - finalize() -> writes Index A and B

- Reader (ArchiveReader):
  - open(path, password=None)
  - list() -> entries
  - extract(entry, out_stream) using index-chunk offsets
  - verify(entry or archive) using chunk/file/merkle checks
  - scan_without_index() -> best-effort sequential listing (recovery mode)

- CLI (amber):
  - create, list, extract, verify, encrypt

Testing Strategy

- Round-trip tests for files/dirs/symlinks; variable chunk sizes; compressed and uncompressed; encrypted and plaintext.
- Corruption tests: flip bits in headers/chunks/index and confirm detection and recovery signals.
- Large file tests with streaming I/O and constant memory footprint.

Open Questions to Resolve Next

- ECC scheme selection and parameters (RS vs RaptorQ), block sizing, and parity placement policy.
- Anchor records design (frequency, content) for improved tail-loss recovery.
- Optional “names-visible” encryption profile (keep index plaintext but encrypt content) vs. v0’s simpler full-archive mode.

Appendix: Minimal Walkthrough Example

1) Write Superblock.
2) For file "docs/guide.txt": EntryBegin(payload: TLV metadata), then Chunk records (each with codec and blake2s_16), then EntryEnd.
3) Repeat for all entries.
4) Build Index (entries list, chunk offsets, per-file blake2s_32, archive merkle root).
5) Write Index A frame + locator, then Index B frame + locator.
6) Close.

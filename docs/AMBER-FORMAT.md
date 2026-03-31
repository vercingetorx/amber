# Amber `.amber` Archive Format

Version: current Rust reference design

## Overview

Amber is a long-term archive container designed for:

- strong integrity
- deterministic repair
- recovery after trailer loss or metadata damage
- canonical rewrite-on-commit mutations

Scope:

- single-file archives
- canonical multipart archives
- optional whole-archive encryption
- append, harden, rebuild, and repair through canonical rewrites

## Goals

- Safety first: strong chunk integrity, archive-level verification, and built-in ECC.
- Determinism: archive structure and repair metadata are reproducible from committed archive state.
- Streaming writes: records can be emitted sequentially and finalized with a trailer/index.
- Random access: the trailer/index provides fast listing, extraction, and verification.
- Reimplementability: fixed endianness, explicit versioning, and stable record structure.

## Non-goals

- in-place mutation as a committed end state
- weak or optional ECC profiles
- per-file encryption modes
- silent recovery or guessed data promotion

## Data model

Entry kinds:

- file
- dir
- symlink

Common metadata:

- UTF-8 normalized relative path
- optional mode
- timestamps where present
- symlink target for symlink entries

File content:

- split into chunks
- uncompressed by default
- optionally compressed
- integrity-tagged per chunk

## Encoding conventions

- fixed-width integers: little endian
- flexible counts and lengths: unsigned LEB128
- header checksum: CRC32C
- integrity and commitment hashing: BLAKE3

## High-level layout

```text
[Superblock]
[Record stream]
[Index frame A]
[Index frame B]
[Locators]
```

Superblock:

- fixed-size public header at logical offset `0`
- carries format identity, version, flags, archive UUID, default chunking, default codec, multipart policy, and encryption/KDF parameters when applicable

Record stream:

- self-delimiting records with CRC-protected headers
- carries entry declarations, chunk payloads, anchors, and parity records

Index/trailer:

- written at finalize time
- contains manifest, chunk map, symbol map, ECC metadata, anchors, and top-level commitments
- stored as redundant trailer frames plus locator records

## Canonical multipart form

Multipart archives are one logical archive split across multiple physical files:

- `archive.amber.001`
- `archive.amber.002`
- `archive.amber.003`

Rules:

- numbering is contiguous from `.001` with no gaps
- the unnumbered base path names the multipart archive set
- the base path must not coexist with a separate single-file archive of the same name
- the trailer must live entirely in the final segment
- all read and mutation operations work from the base path or any segment path

## Encryption

When enabled, Amber uses:

- Argon2id for key derivation
- XChaCha20-Poly1305 for record and trailer encryption
- deterministic keyed BLAKE3 nonce derivation from archive key plus offset/domain material

Encrypted archives:

- protect payloads, parity, anchors, and trailer/index frames
- do not expose plaintext metadata beyond the public superblock fields required to open the archive

## Canonical mutation model

Committed archive state is not “mutated in place” as a logical tail edit.

Canonical mutations:

- stage contents
- write one new archive image
- verify it
- atomically replace the committed archive set

That rule applies to:

- append
- harden
- rebuild
- successful repair

Failed mutation must not leave a partially committed canonical archive image behind.

"""
Amber .amber archive POC

This package provides a minimal writer/reader and CLI for the .amber format
drafted in docs/AMBER-FORMAT.md. Current implementation includes:

- Superblock, Records (EntryBegin/Chunk/EntryEnd), dual Index trailer
- Chunk-level hashing, per-file hashing, and archive-level Merkle
- Optional whole-archive encryption (XChaCha20-Poly1305 via PyCryptodomex)
- ECC: Local Repair Parity (LRP) and RX rateless parity,
  plus tools to repair and to append parity (harden)
- Optional compression using deflate/zlib (codec_id=1)
- Listing, extraction, verification, repair, and harden via CLI

Security note: the index is encoded via a compact TLV format with bounds checks.
When encryption is enabled, both data and metadata (including parity and anchors)
are AEAD‑protected. Always treat untrusted archives defensively and verify before use.
"""

__version__ = "0.1"

__all__ = [
    "constants",
    "writer",
    "reader",
    "ecc",
    "harden",
    "encryption",
]

# Importable programmatic API is available via amber.writer/amber.reader and
# the CLI functions in amber.cli (cmd_seal/cmd_unseal) which take normal parameters.

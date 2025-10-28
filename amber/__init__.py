"""
Amber — opinionated archive tooling focused on security and data integrity.

Features:

- Authenticated record stream (EntryBegin/Chunk/EntryEnd) with dual index trailers.
- Whole-archive AEAD via XChaCha20-Poly1305 with Argon2id key derivation.
- Built-in integrity (chunk tags, per-file hashes, archive Merkle root).
- First-class ECC: Local Repair Parity (LRP) plus RX rateless parity, with CLI helpers
  to verify, repair, harden (append parity), and rebuild damaged archives.
- Append-only workflows preserve existing payloads while refreshing anchors/index metadata.

Everything after the superblock is authenticated; parity and anchors remain encrypted
when a password is provided. See docs/AMBER-FORMAT.md for the on-disk format.
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

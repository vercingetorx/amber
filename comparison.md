Security Posture

    - Amber: Whole-archive AEAD (XChaCha20-Poly1305) with Argon2id KDF is default for encrypted archives, and every record—including parity and anchors—is authenticated. Integrity spans chunk tags, per-file hashes, and a Merkle root, so tampering is caught even when decrypt succeeds. Parity metadata is also encrypted.
    - ZIP/TAR: Classic ZIP’s “standard encryption” is trivially broken; even AES-ZIP variants lack authenticated headers, so bit flips can go unnoticed. TAR has no native encryption or hashing—you must layer tools like GPG and sha256sum.
    - 7z/RAR: Modern revisions offer AES-based encryption with PBKDF2 or custom KDFs and per-block MACs, but still no built-in end-to-end hash for the entire archive; authenticated metadata coverage varies. They do not natively add parity for silent corruption.
    - Restic/Borg-style Repos: Closer peers on security—they combine authenticated encryption with Merkle DAGs and optional redundancy, but they’re backup repositories rather than single-file archives.

Data Integrity & Repair

    - Amber: ECC is first-class. Local Repair Parity guarantees single-symbol recovery per stripe; RX parity adds rateless redundancy for scattered losses. Automated index rebuild plus Merkle verification enables post-corruption healing, even with truncated trailers.
    - ZIP/TAR/7z/RAR: Integrity is mostly checksum-based (CRC32) and non-cryptographic; recovery often means re-downloading or manual repair. Parity/erasure codes are external (PAR2 files, RAID, etc.).
    - Par2: Common companion for archives, but it’s disconnected from the archive structure; Amber’s stripe-aware ECC integrates with metadata for guided repair.

Metadata Resilience

    - Amber: Periodic anchors record symbol windows + Merkle roots; trailer loss is survivable. Index rebuild can operate from content alone, including encrypted cases when password supplied.
    - ZIP/TAR: A broken central directory or trailing metadata can render the archive unreadable; recovery tools guess offsets but lose directory metadata. No parity helps recover enumerations.

Operational Model

    - Amber: Opinionated, security-first: deterministic chunking, fixed KDF settings, and strong defaults. Scrub/harden workflows encourage ongoing maintenance. Append/harden operations preserve payload immutability while refreshing parity and index.
    - Traditional formats: Focus on portability and simple packaging. Security/integrity is optional, left to user discipline.
    - Backup repos (restic, borg): Offer dedupe, retention policies, remote storage—but come with server/client complexity and aren’t meant to hand off as a single archive file.

Trade-offs

    - Amber’s heavy crypto (Argon2id 256 MiB) and ECC increase CPU/memory cost compared to scrypt/lightweight AES zips. Archive size grows with parity (≈8–12% typical). Classic formats win on ubiquity, tooling, and minimal resource requirements.
    - In return, Amber gives you authenticated, self-healing archives—something mainstream formats simply don’t attempt.
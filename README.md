# Amber

Amber is a long-term archive container built for verification, repair, and recovery.

This repository is the Rust reference implementation. It provides:

- the canonical `.amber` archive format implementation
- the `amber` CLI
- the canonical rewrite-on-commit mutation model for append, harden, rebuild, and repair
- the production ECC regime: `AMCF-ECC`

## At a glance

- Long-term archive format with built-in integrity and repair.
- Uncompressed by default to minimize corruption blast radius.
- Optional whole-archive encryption with XChaCha20-Poly1305 and Argon2id.
- One production ECC regime: `AMCF-ECC`.
- Canonical rewrite-on-commit mutation semantics.

## Why Amber

- Strong defaults only.
  - AEAD: XChaCha20-Poly1305
  - KDF: Argon2id with the archive’s fixed parameters
  - Integrity and commitment hashing: BLAKE3
  - ECC: one canonical AMCF policy, not a menu of weak profiles
- Integrity everywhere.
  - Per-chunk tags
  - Per-file hashes
  - Archive Merkle root
  - Periodic anchors
  - Redundant trailer/index copies
- Security over convenience.
  - Encrypted archives do not expose plaintext metadata.
  - Parity and anchors remain encrypted when the archive is encrypted.
  - Maintenance operations require the same credential model as the archive.
- Canonical mutations.
  - Append, harden, rebuild, and successful repair commit one new canonical archive image.
  - Failed mutation does not leave stale live trailer generations behind.

## Quick start

Build the CLI:

```bash
cargo build --release
```

Common commands:

```bash
amber seal --output out.amber path1 path2
amber list out.amber
amber info out.amber
amber verify out.amber
amber unseal out.amber --outdir extracted
amber append out.amber path3
amber harden out.amber --extra-parity-percent 2
amber repair out.amber
amber rebuild out.amber
amber scrub --recursive --repair archives/
```

Encrypted archives:

```bash
amber seal --output secret.amber --password secret path1
amber verify secret.amber --password secret
amber unseal secret.amber --password secret --outdir extracted
```

Keyfile encryption:

```bash
amber seal --output secret.amber --keyfile key.bin path1
amber verify secret.amber --keyfile key.bin
```

Multipart archives:

```bash
amber seal --output backup.amber --part-size 700M bigdir/
```

This produces canonical segment names such as:

- `backup.amber.001`
- `backup.amber.002`
- `backup.amber.003`

All read and mutation commands accept either the base path or any segment path.

## Mutation model

Amber mutations are canonical rewrite-on-commit operations.

- `append` stages prior archive contents plus new inputs, writes one new canonical archive image, verifies it, then swaps it into place.
- `harden` rewrites the archive with a larger canonical AMCF budget.
- `rebuild` writes a fresh canonical archive image and keeps a backup.
- `repair` repairs a work copy and only commits if no damaged data chunks remain.

Operational rules:

- `harden` requires a clean archive.
- If `verify` fails, run `repair` first.
- Safe repair writes a repaired copy rather than mutating the original.

## Compression

Amber stores chunks uncompressed by default.

Why:

- corruption stays more local
- a flipped byte is less likely to destroy a whole chunk
- ECC sees a smaller erasure set

The CLI `--compress` flag currently uses deflate. The library also supports zstd.

## Documentation

- [Format](./docs/AMBER-FORMAT.md)
- [ECC Overview](./docs/AMBER-ECC.md)
- [ECC Design](./docs/AMBER-ECC-DESIGN.md)
- [Damage Model](./docs/AMBER-DAMAGE-MODEL.md)
- [Recovery Spec](./docs/AMBER-RECOVERY-SPEC.md)

## Status

This Rust tree is the reference implementation. The Python tree under `Amber_reference/` remains useful as historical source material, tests, and comparison context, but the canonical implementation and documentation now live here.

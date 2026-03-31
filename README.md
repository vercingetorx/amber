<div align="center">
  <img src="https://raw.githubusercontent.com/vercingetorx/amber/refs/heads/master/resources/amber_logo_small.png" alt="depot_logo" width="250">
</div>

# Amber

Amber is a long-term archive container built for verification, repair, and recovery.

This repository is the Rust reference implementation. It provides:

- the canonical `.amber` archive format implementation
- the `amber` CLI
- the canonical rewrite-on-commit mutation model for append, harden, rebuild, and repair
- the production ECC regime: `AMCF-ECC`

## At a Glance

- Long-term archive format with built-in integrity and repair.
- Uncompressed by default to minimize corruption blast radius.
- Optional whole-archive encryption with XChaCha20-Poly1305 and Argon2id.
- One production ECC regime: `AMCF-ECC`.
- Canonical rewrite-on-commit mutation semantics.

## Why Amber

- Strong defaults only.
  - AEAD: XChaCha20-Poly1305
  - KDF: Argon2id with the archive's fixed parameters
  - Integrity and commitment hashing: BLAKE3
  - ECC: one canonical `AMCF-ECC` policy, not a menu of weak profiles
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
- Self-healing by design.
  - `AMCF-ECC` is Amber's deterministic `GF(256)` archive code.
  - Recovery and rebuild flows can reconstruct canonical metadata from surviving content when the trailer is damaged.
- Canonical mutations.
  - Append, harden, rebuild, and successful repair commit one new canonical archive image.
  - Failed mutations do not leave stale live trailer generations behind.
- Hard to beat ECC.
  - In internal benchmarks, AMCF-ECC recovered more data in nearly every loss scenario than both a strengthened interleaved-overlap Reed-Solomon design and an LRP + RaptorQ-class approach. Where RS and RX failed catastrophically beyond their recovery limits, AMCF degraded gracefully.

## Overview

- Built-in integrity:
  - per-chunk tags
  - per-file hashes
  - archive Merkle root
  - periodic anchors
- Built-in ECC:
  - `AMCF-ECC` = Adaptive Multi-Scale Continuous-Field ECC
  - one deterministic `GF(256)` archive ECC family over storage bytes
  - tiny groups enforce a minimum total parity floor
  - standard groups scale from local structure to broader coupled parity coverage
- Optional whole-archive encryption with XChaCha20-Poly1305 and Argon2id.
  - When enabled, all records are AEAD-protected, including parity and anchors.

## Quick Start

Build the CLI:

```bash
cargo build --release
```

Common commands:

### Seal

```bash
amber seal path1
amber seal path1 path2 --output out.amber
amber seal path1 path2 --output out.amber --compress
amber seal path1 path2 --output out.amber --part-size 700M
amber seal path1 --output out.amber --password secret
amber seal path1 --output out.amber --keyfile /path/to/key.bin
```

### List

```bash
amber list out.amber
amber list out.amber --password secret
amber list out.amber --keyfile /path/to/key.bin
```

### Info

```bash
amber info out.amber
```

### Unseal

```bash
amber unseal out.amber --outdir extracted/
amber unseal out.amber --outdir extracted/ --password secret
```

### Append

```bash
amber append out.amber path1 path2
amber append out.amber path1 --password secret
amber append out.amber path1 --keyfile /path/to/key.bin
```

### Verify

```bash
amber verify out.amber
amber verify out.amber --password secret
```

### Repair

```bash
amber repair out.amber
amber repair out.amber --safe
amber repair out.amber --password secret
```

### Harden

```bash
amber harden out.amber
amber harden out.amber --extra-parity-percent 2
amber harden out.amber --password secret
```

`harden` refuses to run unless the archive already verifies clean.

### Rebuild

```bash
amber rebuild out.amber
amber rebuild out.amber --password secret
amber rebuild out.amber --keyfile /path/to/key.bin
```

### Scrub

```bash
amber scrub /path/to/archives --recursive --repair
```

## Multipart Archives

- Amber supports canonical multipart output at seal time.
- Use `--part-size` to split one logical archive across multiple physical files:

```bash
amber seal photos/ --output backup.amber --part-size 700M
```

- This produces files like:
  - `backup.amber.001`
  - `backup.amber.002`
  - `backup.amber.003`
- The base path `backup.amber` names the multipart archive set. It must not coexist with a separate single-file `backup.amber` archive.
- Segment numbering is contiguous. A missing numbered segment is a hard archive error, not a shorter valid archive.
- Sealing fails if any conflicting namespace member already exists for that base path, including stale numbered segments.
- You can open, list, verify, unseal, rebuild, repair, append, and harden a multipart archive from the base path or from any segment path.
- Multipart mutating commands operate on the logical archive and preserve the segmented layout.

## Compression Tradeoff

- Default behavior stores data chunks uncompressed.
  - Benefit: corruption stays more local.
  - A flipped bit or byte is far less likely to destroy a whole chunk.
  - ECC sees a smaller erasure set.
  - Cost: larger archives on disk.

- `--compress` stores data chunks with deflate.
  - Benefit: smaller archives.
  - Cost: one flipped bit inside a compressed chunk will usually invalidate that entire chunk.

- Practical rule:
  - if the archive is meant to be a long-term, repairable copy, the default uncompressed mode is usually the right choice

## Mutation Model

Amber mutations are canonical rewrite-on-commit operations.

- `append` stages prior archive contents plus new inputs, writes one new canonical archive image, verifies it, then swaps it into place.
- `harden` rewrites the archive with a larger canonical AMCF budget.
- `rebuild` writes a fresh canonical archive image and keeps a backup.
- `repair` repairs a work copy and only commits if no damaged data chunks remain.

Operational rules:

- `harden` requires a clean archive.
- If `verify` fails, run `repair` first.
- Safe repair writes a repaired copy rather than mutating the original.

## Best Practices

- Keep redundancy.
  - Maintain at least two independent copies on separate media or sites.
- Scrub regularly.
  - Cold data: quarterly.
  - Active archives: monthly.
  - Use `amber verify` for quick checks.
  - Use `amber scrub --repair` for fleet maintenance.
- Repair before hardening.
  - If `verify` fails, run `amber repair`, then verify again.
  - Run `amber harden` only once `amber verify` passes.
  - If you see repair events, adding `1-3%` more AMCF parity is a reasonable way to restore margin.
- After moving archives to new media:
  - run `verify`
  - consider `harden` to refresh parity margin

## Repair Model

- Symbol size is `64 KiB`.
- Any number of bit/byte flips within one symbol count as one symbol erasure.
- Repair strength depends on group shape and total parity budget.
- In standard archive groups, `AMCF-ECC` is designed to survive mixed damage patterns including:
  - random symbol loss
  - short symbol windows
  - tail damage
  - some parity loss alongside data loss
- In tiny groups, Amber enforces a minimum total parity floor.
- ECC operates over storage bytes after compression and encryption.
- Parity records are encrypted when the archive is encrypted.
- For compressed archives, one flipped bit inside a stored chunk will usually invalidate that entire chunk.
  - In that case, the practical repair unit is often a damaged chunk rather than an isolated bit.

## Documentation

- [Format](./docs/AMBER-FORMAT.md)
- [ECC Overview](./docs/AMBER-ECC.md)
- [ECC Design](./docs/AMBER-ECC-DESIGN.md)
- [Damage Model](./docs/AMBER-DAMAGE-MODEL.md)
- [Recovery Spec](./docs/AMBER-RECOVERY-SPEC.md)

## Status

This repository is the reference implementation and the canonical operator documentation for Amber.

<div align="center">
  <img src="https://raw.githubusercontent.com/vercingetorx/amber/refs/heads/master/resources/amber_logo_small.png" alt="depot_logo" width="250">
</div>

# Amber

Amber is a long-term archive container built for verification, repair, and recovery.

This repository is the Rust reference implementation. It provides:

- the canonical `.amber` archive format implementation
- the `amber` CLI
- the canonical rewrite-on-commit mutation model for append, harden, rebuild, and repair
- the archive ECC scheme: `Cauchy Reed-Solomon ECC`

## At a Glance

- Long-term archive format with built-in integrity and repair.
- Uncompressed by default to minimize corruption blast radius.
- Optional whole-archive encryption with XChaCha20-Poly1305 and Argon2id.
- One archive ECC scheme: `Cauchy Reed-Solomon ECC`.
- Canonical rewrite-on-commit mutation semantics.

## Why Amber

- Fixed archive policies.
  - AEAD: XChaCha20-Poly1305
  - KDF: Argon2id with the archive's fixed parameters
  - Integrity and commitment hashing: BLAKE3
  - ECC: one canonical `Cauchy Reed-Solomon ECC` policy
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
- Repair metadata.
  - `Cauchy Reed-Solomon ECC` is Amber's deterministic global `GF(2^16)` archive code.
  - Recovery and rebuild flows can reconstruct canonical metadata from surviving content when the trailer is damaged.
- Canonical mutations.
  - Append, harden, rebuild, and successful repair commit one new canonical archive image.
  - Failed mutations do not leave stale live trailer generations behind.

## Overview

- Built-in integrity:
  - per-chunk tags
  - per-file hashes
  - archive Merkle root
  - periodic anchors
- Built-in ECC:
  - `Cauchy Reed-Solomon ECC` = Cauchy-form Reed-Solomon erasure correction
  - one deterministic `GF(2^16)` Cauchy construction over stored archive symbols
  - every repair symbol is a dense equation over the full protected symbol set
  - with `R` available repair symbols, the code can recover any `R` missing or corrupt data symbols in the protected set
- Optional whole-archive encryption with XChaCha20-Poly1305 and Argon2id.
  - When enabled, all records are AEAD-protected, including parity and anchors.

## ECC Recovery Model

Amber uses one Cauchy Reed-Solomon recovery set over the archive's stored symbols:

```text
N data symbols + R repair symbols
recover any R erased/corrupt data symbols, assuming R repair symbols remain available
```

The implementation uses `GF(2^16)` Cauchy coefficients, so one protected set must satisfy:

```text
data_symbols + repair_symbols <= 65,536
```

Amber’s symbol size is the scaling knob for large archives. The code protects stored archive symbols, not individual bytes.

## Quick Start

Build the CLI:

```bash
cargo build --release
```

Dependency policy:

- Amber intentionally uses wildcard dependency requirements and commits `Cargo.lock`.
- Reproducible application builds are lockfile-based.
- Dependency refreshes are treated as whole-ecosystem updates rather than per-crate version maintenance.

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

### Salvage

```bash
amber salvage out.amber --outdir recovered/
amber salvage out.amber --outdir recovered/ --password secret
```

`salvage` extracts only files whose chunks validate completely. Corrupted or incomplete files are skipped, and failed file attempts do not leave partial output under the final filename.

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
- You can open, list, verify, unseal, salvage, rebuild, repair, append, and harden a multipart archive from the base path or from any segment path.
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
- `harden` rewrites the archive with a larger canonical Cauchy RS budget.
- `rebuild` writes a fresh canonical archive image and keeps a backup.
- `repair` repairs a work copy and only commits if no damaged data chunks or damaged Cauchy RS parity symbols remain.

Operational rules:

- `harden` requires a clean archive.
- `append` requires a clean archive.
- `verify` checks payload readability and reports damaged repair redundancy as a warning.
- If `verify` fails, run `repair` first.
- Safe repair writes a repaired copy rather than mutating the original.

## Best Practices

- Keep redundancy.
  - Maintain at least two independent copies on separate media or sites.
- Scrub regularly.
  - Cold data: quarterly.
  - Active archives: monthly.
  - Use `amber verify` for quick payload checks.
  - Use `amber scrub --repair` for full archive-health maintenance, including Cauchy RS parity.
- Repair before hardening.
  - If `verify` fails, run `amber repair`, then verify again.
  - Run `amber harden` only once `amber verify` passes and `amber scrub` reports no damaged repair redundancy.
  - If repair consumes parity, use `amber harden` to add more Cauchy RS repair symbols.
- After moving archives to new media:
  - run `verify`
  - consider `harden` to refresh parity margin

## Repair Model

- Amber chooses the archive symbol size before writing so that the protected data symbols plus repair symbols fit in one `GF(2^16)` Cauchy RS set.
- The default symbol size is `64 KiB`; large archives use larger symbols to keep one recovery set.
- Any number of bit or byte errors inside one stored symbol count as one symbol erasure once verification localizes the damage.
- With `R` surviving repair symbols, Cauchy RS repair can recover any `R` missing or corrupt data symbols in the protected set.
- Parity damage consumes parity margin: damaged repair symbols are not available to repair data until they are recomputed.
- Tiny archives still receive a minimum total parity floor.
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

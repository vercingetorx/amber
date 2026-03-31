# AMCF-ECC Design

Status:

- current production ECC design for Amber
- canonical architecture document

## What AMCF-ECC is

`AMCF-ECC` means Adaptive Multi-Scale Continuous-Field ECC.

It is Amber’s production archive ECC regime: a deterministic `GF(256)` code designed for real archive damage, not a neat fixed packet block.

At a high level it combines:

- dense algebra where tiny systems need raw rank
- larger structured parity generation for bigger groups
- explicit cleanup rank where sparse-style recovery alone is insufficient

## Design constraints

Amber ECC must satisfy all of these at once:

- deterministic encode and decode behavior
- appendable archive growth
- parity over stored bytes
- compatibility with canonical rewrite-on-commit mutation
- repair after mixed data and parity damage
- stable archive metadata needed for reimplementation years later

## Storage domain

AMCF protects stored bytes.

That means:

- plaintext archives: parity covers stored chunk bytes
- encrypted archives: parity covers ciphertext bytes

This is deliberate. Amber repairs what is physically present in the archive.

Implication:

- compressed chunks often fail as whole chunks after even a small byte error
- uncompressed storage keeps the practical damage unit smaller

## Why AMCF is multi-regime

Archive groups fail differently at different scales.

Tiny groups:

- fail like small linear systems
- are dominated by equation count and rank

Larger groups:

- need better locality and broader resilience together
- must tolerate random loss, localized loss, and mixed damage

One regime shape does not serve all of those equally well, so AMCF uses scale-appropriate construction under one deterministic family.

## Operational properties

AMCF is designed to support:

- seal-time parity generation
- append without rewriting prior groups
- later hardening that adds new parity budget canonically
- repair that uses the archive’s committed ECC metadata
- recovery when trailer/index metadata must first be rebuilt from surviving records

## Canonical policy

Amber uses one production ECC policy.

Notable rules:

- tiny groups enforce a minimum total parity floor of `6`
- hardening increases parity budget canonically
- repair never promotes guessed data
- harden requires a clean archive

## Practical intent

AMCF is not trying to be the prettiest block code on paper.

It is trying to be strong under the damage Amber actually faces:

- random symbol loss
- contiguous windows and bursts
- tail damage
- mixed data and parity damage
- metadata-first survivability failures

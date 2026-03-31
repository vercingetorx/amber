# Amber Recovery Spec

Purpose:

- define the recovery architecture Amber optimizes for
- specify what archive recovery must accomplish
- turn “best long-term recoverability possible” into explicit engineering requirements

## Recovery goals

- maximize the probability of full archive recovery after realistic storage damage
- when full recovery is impossible, maximize verified structural recovery
- never promote guessed or weakly inferred data as valid recovered output

## Recovery principles

- structure first
- verification first
- graceful degradation
- damage-model alignment
- append-friendly evolution through later hardening

## Recovery outcomes

- full recovery
  - all contents and metadata restored exactly and verify cleanly
- structural recovery
  - entry boundaries, layout, and surviving file inventory reconstructed even if some payload is gone
- file-level partial recovery
  - some files fully recovered and verified while irrecoverable regions remain explicit
- integrity-preserving failure
  - the system refuses to claim recovery where correctness cannot be established

## Recovery phases

Phase 0: archive identification

- validate superblock
- establish archive UUID, version, encryption state, and baseline parameters

Phase 1: surviving-structure discovery

- locate surviving trailer/index frames and locators
- locate surviving anchors
- scan records forward when the trailer is absent or untrusted

Phase 2: damage localization

- identify unreadable or inconsistent regions
- verify record headers, chunk records, anchors, and parity descriptors
- mark damaged payloads as erasures or contradictions

Phase 3: structural repair

- rebuild index-equivalent metadata from surviving records
- reconstruct entry layout, chunk maps, symbol maps, and parity references

Phase 4: content reconstruction

- apply the archive ECC to damaged or missing regions
- preserve verified good data and minimize unnecessary rewriting

Phase 5: verification and promotion

- recheck chunk tags, file hashes, Merkle roots, and structural commitments
- promote reconstructed data only after the relevant checks pass

Phase 6: post-recovery hardening

- optionally emit a canonically rewritten archive with fresh structural metadata and updated parity state

## Required capabilities

- trailer independence
  - recovery remains possible when one or both trailer copies are gone
- metadata reconstruction
  - reader state can be rebuilt from surviving records
- parity-aware repair
  - repair handles damaged data and damaged parity together
- encryption-aware recovery
  - encrypted archives require correct credentials for encrypted content recovery
- canonical promotion
  - successful repair commits a canonical archive image rather than leaving stale logical metadata behind

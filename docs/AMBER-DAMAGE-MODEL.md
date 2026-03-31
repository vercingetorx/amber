# Amber Damage Model

Purpose:

- define the failure assumptions Amber is designed to survive
- separate the damage model from any single algorithmic implementation detail
- give recovery and hardening policy a stable target

## Scope

Amber is designed for long-term archives at rest, including archives that are:

- verified
- scrubbed
- repaired
- hardened
- stored as single-file or canonical multipart archives

Primary emphasis:

- non-adversarial storage degradation
- operator mistakes second
- active attack resistance third

## Recovery objective

Primary objective:

- maximize the probability of recovering original archive contents after realistic long-term storage damage

Secondary objective:

1. preserve archive structure and interpretability
2. preserve file boundaries and metadata
3. preserve intact file contents
4. preserve any verified partial recovery that remains possible

## Threat classes

Amber is built around these damage classes:

- isolated byte corruption
- symbol- or sector-scale unreadability
- contiguous burst loss
- trailer and tail loss
- metadata-first survivability failure
- correlated medium aging
- maintenance-window degradation where originally adequate parity margin is no longer enough years later

## Archive information hierarchy

- Layer 0: format identity and superblock
- Layer 1: structural metadata
- Layer 2: layout metadata
- Layer 3: integrity commitments
- Layer 4: payload and parity bytes

Recovery should preserve higher layers before claiming lower-layer success.

## Design implications

- trailer loss must not make surviving payload unrecoverable by itself
- metadata reconstruction matters as much as raw ECC repair
- random and localized loss both matter
- parity loss alongside data loss is part of the expected model
- hardening must be possible later as medium health assumptions change

## Practical note on compression

Compression changes the practical damage unit.

- uncompressed archives usually localize damage better
- compressed chunks often become whole-chunk erasures after small corruption

That is why Amber defaults to uncompressed storage.

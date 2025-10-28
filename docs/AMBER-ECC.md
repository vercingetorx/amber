Amber ECC — Adaptive Multi‑Scale Error Correction (AMSEC)

Version: v0 design (for .amber v1.0)

Summary

- AMSEC combines two complementary layers:
  - LRP (Local Repair Parity): lightweight, locality‑aware XOR parity across small symbol groups for fast one‑off repairs with minimal overhead and I/O.
- RX (Raptor‑style deterministic rateless parity): a rateless, GF(2^8) random linear code over large windows that reconstructs lost symbols with high probability at low overhead. RX uses a tiny virtual precode and a fixed small degree band to enable fast peeling, with a sparse elimination fallback on the residual. Parities are fully deterministic from a seed, enabling append and stateless replay.
- Together they deliver robust recovery from bit flips, small bursts, and multi‑symbol loss without Reed‑Solomon. Bit flips are detected at fine granularity and treated as erasures for RX when local repair does not suffice.
- Parity can be appended after archive creation (“progressive hardening”), and is computed over stored bytes (ciphertext if encrypted) to preserve confidentiality and allow recovery without keys.

Threat Model and Objectives

- Bit rot (random bit flips), small bursts (scratched sectors), localized region loss, and tail damage.
- Minimize parity overhead (target 2–8% typical), while keeping recovery probability > 0.999999 for expected loss patterns.
- Preserve streaming writes; enable random access and partial verification; operate across compressed and/or encrypted payloads without breaking authenticity.

Design Principles

- Detect, then correct: fine‑grained cryptographic tags identify the smallest corrupted unit; correction treats those units as erasures.
- Multi‑scale resilience: small, local parity fixes the common case quickly; a rateless RX layer handles worst‑case multi‑loss.
- Rateless and appendable: more parity can be generated later and appended as new ECC frames, boosting durability over time without rewriting the archive.
- Storage‑domain coding: parity is over the bytes as stored on disk (post‑compression, post‑encryption), preserving privacy and matching the failure domain. Parity Records are encrypted/authenticated like any other Record when archives are encrypted.

Terminology

- Symbol: the atomic ECC unit. Default size S_sym = 64 KiB (configurable per ECC group).
- Source symbol: a symbol derived from archive data bytes.
- Parity symbol: a symbol produced by LRP (XOR across a small set) or by RX (random linear combination across a large set).
- Window: a contiguous index range of source symbols covered by an RX group (e.g., 4096 symbols = 256 MiB at 64 KiB symbols).

Integrity and Erasure Labelling

- Every stored symbol carries a 16‑byte BLAKE2s tag (truncated) computed over the symbol’s storage bytes. Tags live in the Index for compactness; writers may also include symbol tags in Anchor records for scan‑without‑index recovery.
- During verification, any tag mismatch marks that symbol as an erasure for ECC decoding.

Layer 1 — LRP: Local Repair Parity (optional but recommended)

- Purpose: instant, low‑I/O recovery for single‑symbol loss within a small neighborhood. Excellent for isolated bit‑rot or a single bad sector.
- Construction:
  - Partition source symbols into small stripes of size k_L (e.g., 8 or 12 symbols). For each stripe, compute p_L XOR parity symbols, typically p_L=1.
  - Interleave stripes so that adjacent physical sectors do not share the same stripe (spreads burst damage).
- Overhead: p_L/k_L. Example: k_L=12, p_L=1 → 8.3% (can be set lower, e.g., k_L=16 → 6.25%). LRP can be disabled (p_L=0) when overhead budget is very tight and RX is relied upon.
- Recovery: if ≤ p_L symbols in a stripe are marked as erasures, recover by XOR without global decode.

Layer 2 — RX: Deterministic Rateless Parity (core)

- Purpose: high‑probability recovery from multiple erasures scattered across a large window, with small overhead and no fixed MDS structure.
- Field: GF(2^8). Efficient on CPUs and amenable to SIMD; avoids RS’s heavy Galois field polynomials per stripe while retaining strong linear independence properties.
- Rateless construction:
  - For a window of N source symbols, generate M parity symbols. Overhead ε = M/N (recommend ε = 0.02–0.06 for most archives).
  - Each parity symbol i is defined by a seed s_i. Using s_i and group parameters, a PRNG deterministically samples:
    - a small degree d ∈ {3,4,5} (capped by N),
    - neighbors drawn from the union of data symbols and a tiny pool of virtual precode nodes P≈1%·N; each precode node expands into a few data neighbors when evaluated,
    - non‑zero coefficients in GF(256) per neighbor.
  - Always include a deterministic data pivot (i mod N) for coverage. Apply rank verification against previously accepted rows and, if dependent, deterministically resample.
  - The parity payload is the linear combination: y_i = Σ_j c_{ij} · x_{idx_{ij}} over GF(256).
- Decoding:
  - Identify erased symbols via tags (and any entirely missing records).
  - Run peeling first (degree‑1 elimination). If stalled, perform sparse Gaussian elimination on the small residual.
  - With typical ε and distributions, recovery succeeds with very high probability; failure probability decays exponentially with ε and window size.
- Why not RS: RX is rateless (M chosen after the fact), appendable, and keeps encoding/decoding cost proportional to recovered symbols rather than fixed per‑stripe coding.

Interleaving and Windows

- Windows: choose N so a window fits in comfortable memory during recovery (e.g., 4096–16384 symbols → 256 MiB–1 GiB at 64 KiB symbols). Windows may be adjacent with small overlaps to guard boundary effects.
- Interleaving: apply a pseudorandom permutation P to map logical symbol order to physical reference order for LRP and RX sampling. P is derived from archive_uuid and group_id, reducing spatial correlation and mitigating burst loss.

Progressive Hardening (Append‑Only Parity)

- Additional RX parity frames can be appended later with new seeds and the same windowing parameters. Readers merge all parity frames for a group during recovery.
- This supports “age‑based” hardening: start with ε=2% and, years later, append another 2% to restore safety margins after media health changes.

Domain and Encryption

- ECC operates over storage bytes:
  - plaintext archives: over compressed chunk payloads.
  - encrypted archives: over ciphertext. This preserves confidentiality; parity does not leak plaintext.
- AEAD integrity: ECC does not replace AEAD; it allows reconstructing ciphertext bytes. Decryption/authentication still uses the original AEAD tags.

Format Additions (to .amber Index/ECC descriptors)

- ECC Group Descriptor (CBOR, referenced from the Index):
  - group_id u32
  - domain u8: 0=storage_bytes
  - symbol_size u32 (bytes), default 65536
  - window { start_symbol u64, symbol_count u32 }
  - interleave_seed bstr[16]
  - lrp { k_L u16, p_L u8 } (optional; p_L=0 if absent)
  - grf { epsilon_ppm u32, dist_id u16, coeff_field u8=8, seed_base bstr[16] }
  - sources: compact run‑length description of source symbols in this window
  - parity_refs: array of parity record locators ({offset u64, len u32, seed_id u32})
  - symbol_tags_root bstr[32] (Merkle root of per‑symbol BLAKE3‑16 tags for this window; enables partial reconstruction without full Index)

- Parity Records (stored as Chunk records with special codec_id):
  - codec_id = 0x8101 for LRP XOR parity (indicates k_L, stripe_id in header ext)
  - codec_id = 0x8201 for RX parity (indicates seed_id; payload is one parity symbol)
  - rflags bit set to indicate parity; entry_id = 0 (not associated with a file)

Deterministic Sampling Details (RX)

- degree band: fixed small set {3,4,5} (capped by N); neighbors drawn from data ∪ a small virtual precode pool P≈1%·N.
- sampling PRNG: deterministic stream keyed from seed_base and seed_id, with per‑attempt derivation for rank‑check retries.
- pivot coverage: always include data index (seed_id mod N).
- coefficients: non‑zero GF(256) bytes using a fixed irreducible polynomial (0x11D).

Decoding Workflow

- Input: damaged archive, ECC descriptors, symbol tags (from Index or Anchor).
- Step 1: Locate erasures by verifying symbol tags and record headers.
- Step 2: LRP pass — for each stripe with ≤ p_L erasures, recover by XOR and re‑verify tags.
- Step 3: RX pass — build the sparse system for remaining erasures within each window, run peeling; if stuck, apply small dense elimination on the residual.
- Step 4: Write recovered storage bytes back in memory, then continue standard verification (AEAD decrypt + file digests as needed).

Overhead and Expected Recovery

- Example configs (symbol 64 KiB, window 4096 symbols ~256 MiB):
  - “Lean”: LRP off, RX ε=0.03 → recovers up to ~3% random symbol loss with failure probability < 10^-9; burst resilience via interleaving.
  - “Balanced”: LRP 1/16 (6.25%), RX ε=0.02 → near‑instant single‑symbol fixes; multi‑loss handled by RX with very high success; total ≈ 8.25%.
  - “Archival”: LRP 1/12 (8.3%), RX ε=0.04 → strong resilience to clustered faults; total ≈ 12.3%.
- Practically, random bit flips are detected at symbol granularity and treated as single‑symbol erasures; even the “Lean” profile corrects them with modest overhead.

Complexity

- Encoding: LRP O(bytes), RX O(ε·bytes) with light GF(256) ops; easily parallel across windows.
- Decoding: peeling is near‑linear in unknowns; residual elimination cost is bounded by a small pivot set (tens to low hundreds), keeping RAM and time practical on commodity hardware.

Recovery Without the Trailer

- Anchor records (if present) carry a rolling subset of symbol tags and ECC pointers, enabling best‑effort recovery even if both Index copies are lost. Fallback is a forward scan to rebuild minimal metadata and then RX decode within discovered windows.

Security Considerations

- ECC parity reveals only linear relations over storage bytes. When domain=storage_bytes and the archive is encrypted, parity is over ciphertext and leaks nothing about plaintext.
- Symbol tags are cryptographic; undetected corruption is extremely unlikely. All ECC references are authenticated via the Index hash and the archive Merkle root.

POC Implementation Notes (Python)

- Dependencies: hashlib (blake2s), zlib, pickle, crc32c, and a small GF(256) math layer (implemented in pure Python).
- Start with: symbolization, per‑symbol tags, LRP (XOR) encoder/decoder, then RX encoder; implement peeling + fallback sparse elimination.
- Provide a CLI to generate and append parity frames and to verify/repair archives.

Open Questions and Future Work

- Degree band and precode sizing vs. ε for fastest peeling.
- Anchor record format (what subset of tags and references to include and how frequently).
- Optional micro‑ECC within symbols (e.g., tiny BCH/LDPC to correct a few random flips without treating a full symbol as an erasure) — keep optional to avoid bloat.
Presets and SLOs (Operational)

- lean
  - Overhead: ≈2% (RX only)
  - SLO: high‑probability recovery of up to ~ε scattered symbol erasures per window; pair with a second copy.
- balanced (default)
  - Overhead: ≈8.25% (LRP 1/16 + RX 2%)
  - SLO: guaranteed single‑symbol repair per stripe via LRP; RX covers additional scattered losses with high probability.
- archival
  - Overhead: ≈12.3% (LRP 1/12 + RX 4%)
  - SLO: additional margin for clustered damage/weaker media; LRP guarantee plus larger RX headroom.

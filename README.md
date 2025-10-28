Amber — Robust Long‑Term Archive Container

Why Amber?

Amber is unapologetically opinionated. The focus is long-term safety, not a kitchen sink of toggles:

- Strong defaults only: AEAD is XChaCha20‑Poly1305, keys come from Argon2id (256 MiB / 3 passes / 4 lanes), and ECC always emits the same stripe and RX budgets. There are no weak knobs to misconfigure.
- Integrity everywhere: every chunk, file, index, anchor, and parity record is authenticated and hashed. Merkle roots and periodic anchors make trailer loss survivable.
- Security over convenience: encrypted archives never leak metadata, and parity stays encrypted so attackers learn nothing about the plaintext from redundancy. Supplying the password is mandatory for maintenance operations by design.
- Self-healing by design: Local Repair Parity plus RX parity gives single-symbol guarantees and probabilistic recovery for wider loss. Rebuild workflows operate from content alone when trailers are gone.
- Minimal dependencies (for optional encryption): just PyCryptodomex and argon2‑cffi.

Amber is not for everyone but if you want a secure archive that stays verifiable and repairable years later—with one set of hardened assumptions—this is the bar we guarantee.

Overview

- Modern, future‑proof archive focused on long‑term safety against bit rot.
- Built‑in integrity (per‑chunk tags, per‑file hash, archive Merkle) and ECC (LRP + RX).
  - LRP = Local Repair Parity (small XOR stripes over storage bytes)
  - RX = Raptor‑style deterministic rateless parity (seeded, appendable)
- Optional whole‑archive encryption (XChaCha20‑Poly1305) with Argon2id key derivation. When enabled, all records are AEAD‑protected, including parity and anchors.

Quick Start

- Seal an archive
  - `amber seal out.amber path1 path2 ...`
  - Encrypted: `amber seal out.amber path1 ... --password secret`
- List contents
  - `amber list out.amber`
  - Encrypted: `amber list out.amber --password secret`
- Unseal (extract) everything
  - `amber unseal out.amber --outdir extracted/`
- Append files to an existing archive (safe append)
  - `amber append out.amber path1 path2 ...`
  - Encrypted: `amber append out.amber path1 ... --password secret`
- Verify integrity (scrub)
  - `amber verify out.amber`
- Rebuild archive (full rewrite with staging + atomic swap + `.bak` backup)
  - `amber rebuild out.amber`
  - Encrypted: add `--password secret`
- Attempt repair (in-place metadata rebuild + ECC fix)
  - `amber repair out.amber`
- Append extra parity (harden)
  - Default is balanced (+2% RX): `amber harden out.amber`
  - Explicit amount: `amber harden out.amber --extra-ppm 20000`
  - Harden refuses to run unless the archive verifies clean; make sure `amber verify` (and `amber repair`) succeed first.

Using Amber as a Library

```python
from amber.cli import cmd_seal, cmd_unseal, cmd_verify

# Seal an archive (same defaults as the CLI)
cmd_seal(
    "backup.amber",
    ["docs", "photos"],
    password="correct horse battery staple",
)

# Verify later
cmd_verify("backup.amber", password="correct horse battery staple")

# Extract a subset of paths
cmd_unseal(
    "backup.amber",
    outdir="restore/",
    password="correct horse battery staple",
    paths=["docs/report.pdf"],
    exists="rename",
)
```

For more control (streaming or custom ECC), you can use the writer/reader classes directly:

```python
from amber.writer import ArchiveWriter
from amber.reader import ArchiveReader

with ArchiveWriter("project.amber", password="secret") as w:
    w.add_dir("src", mode=0o755)
    w.add_file("src/main.py", "/workspace/main.py")
    w.finalize()

with ArchiveReader("project.amber", password="secret") as r:
    for entry in r.list():
        print(entry.path, entry.size)
```

Best Practices (Recommended)

- Keep redundancy
  - Maintain at least two independent copies (separate disk/site). One copy + parity is better than nothing, but two copies is the baseline for long‑term retention.

- Choose a parity profile (storage overhead → resilience)
  - Lean: RX ~2% (no LRP)
    - Overhead: ≈2%
    - SLO: high‑probability repair of scattered random symbol losses up to ~ε per window; rely on a second copy for belt‑and‑suspenders.
  - Balanced: LRP 1/16 (~6.25%) + RX 2% (≈8.25% total)
    - Overhead: ≈8.25%
    - SLO: guaranteed 1‑symbol repair per stripe (LRP); plus high‑probability recovery of additional scattered losses (RX).
  - Archival: LRP 1/12 (~8.3%) + RX 4% (≈12.3% total)
    - Overhead: ≈12.3%
    - SLO: stronger margin for clustered faults or weaker media; same LRP guarantee + higher RX headroom.

- Scrub regularly (verify)
  - Cold data: quarterly. Active archives: monthly.
  - Command: `amber verify out.amber`
  - If verify fails, run: `amber repair out.amber`, then verify again.

- Harden after clean verifies or repairs
  - Run `amber harden` only once `amber verify` passes (the command rechecks internally and aborts on dirty archives).
  - If you see any repair events, add +1–2% RX to restore safety margins.
  - Command: `amber harden out.amber --extra-ppm 20000`
  - You can harden encrypted archives too: add `--password`.

- Use a checksumming filesystem if possible
  - ZFS/btrfs help detect underlying corruption even without ECC RAM.
  - Still keep periodic archive verifies; they validate the full storage domain bytes.

- Non‑ECC RAM considerations
  - Creation/repair uses cryptographic tags; results are verified before committing. Nonetheless, transient memory faults can cause crashes/retries.
  - The mitigation is routine verify + redundancy (a second copy) rather than relying on a single instance.

- Migration and backups
  - After moving archives to new media, run `verify` and consider `harden` to refresh parity margins.

What “Start Lean, Append Later” Means

- Begin with a small but meaningful RX budget (e.g., 2–3%).
- As media ages or after any repair event, append +1–2% parity.
- Appending writes parity and a refreshed index; the original payload is not rewritten.
- Never append parity on a dirty (unrepaired) archive.

How Much Corruption Can Be Repaired?

- Symbol size: 64 KiB. Any number of bit/byte flips within one symbol count as one erasure.
- LRP stripes: k data + 1 parity (default k=16 balanced, k=12 archival). Repairs up to one symbol per stripe (guaranteed).
- RX parity (default ~2%) repairs ≈2% of symbols per window/archive (high probability), including cases where some stripes lose more than one symbol.
- ECC operates over storage bytes (post‑compression, post‑encryption). Parity records themselves are encrypted when the archive is encrypted.

Troubleshooting

- Friendly errors: CLI prints concise messages (e.g., missing password, file not found) and exits non‑zero.
- Corruptor helper to simulate bit flips:
  - Random default (no password needed): `python3 -m amber.corrupt out.amber`
  - By offset: `python3 -m amber.corrupt by-offset out.amber --offset 4096`
  - Symbol‑aware (needs password if encrypted): `python3 -m amber.corrupt first-symbol out.amber --password "secret"`

References

- Format: `docs/AMBER-FORMAT.md`
- ECC design (AMSEC): `docs/AMBER-ECC.md`

Append model and anchors

- Appends reopen the archive, truncate to the last valid anchor, and write new records; the original payload is preserved.
- A new ECC group is created for appended symbols; previous groups remain immutable.
- Anchors are periodic records carrying a small rolling window of ECC symbol metadata and the current Merkle root to enable recovery if the trailer is lost.
- Finalization writes fresh dual index frames and locators; anchors are also emitted periodically during large writes (default interval: 64 MiB of data symbols).

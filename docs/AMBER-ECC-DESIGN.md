# Cauchy Reed-Solomon ECC Design

Status:

- current archive ECC design for Amber
- canonical architecture document

## What Cauchy Reed-Solomon ECC is

`Cauchy Reed-Solomon ECC` is Amber's global maximum-distance-separable archive ECC.

Amber splits stored archive bytes into fixed-size symbols. It then emits dense global repair symbols using a deterministic Cauchy matrix over `GF(2^16)`.

For a protected set with `N` data symbols and `R` available repair symbols, the recovery guarantee is:

```text
recover any R erased or corrupt data symbols
```

That is the maximum possible full-recovery guarantee for `R` repair symbols.

## Design constraints

Amber ECC must satisfy all of these at once:

- deterministic encode and decode behavior
- parity over stored bytes
- compatibility with canonical rewrite-on-commit mutation
- repair after mixed data and parity damage
- stable archive metadata needed for reimplementation years later
- deterministic coefficient and row construction

## Storage domain

Cauchy Reed-Solomon protects stored bytes.

That means:

- plaintext archives: parity covers stored chunk bytes
- encrypted archives: parity covers ciphertext bytes

This is deliberate. Amber repairs what is physically present in the archive.

Implication:

- compressed chunks often fail as whole chunks after even a small byte error
- uncompressed storage keeps the practical damage unit smaller

## Construction

For `N` data symbols and `R` repair rows, Amber requires:

```text
N + R <= 65,536
```

The implementation assigns Cauchy tags as:

```text
column_tag[i] = i
row_tag[r]    = N + r
```

The coefficient for repair row `r` and data symbol `i` is:

```text
inverse(row_tag[r] XOR column_tag[i]) in GF(2^16)
```

Because all row tags are distinct, all column tags are distinct, and the two tag ranges are disjoint under the bound above, every square submatrix of the Cauchy matrix is nonsingular. That is why the Reed-Solomon construction is maximum-distance-separable.

Each repair symbol is dense: it contains one `GF(2^16)` linear combination of every data symbol, applied lane-by-lane across the stored symbol bytes.

## Operational properties

Cauchy Reed-Solomon supports:

- seal-time parity generation
- later hardening that appends additional repair rows canonically
- repair that uses the archive's committed ECC metadata
- recovery when trailer/index metadata must first be rebuilt from surviving records

Hardening does not change existing row definitions. Row `r` is always the same Cauchy row for a given data-symbol count. Adding parity appends later rows.

The archive commits its symbol size in ECC metadata and anchor records. Anchor records also contain a compact metadata checkpoint: archive UUID, symbol size, Cauchy RS scheme, symbol counts, seed base, Merkle root, and a BLAKE3 hash over those fields. Rebuild uses validated checkpoints or parity records to recover the committed symbol size before reconstructing the symbol table.

## Canonical policy

Amber uses one archive ECC policy.

Notable rules:

- the on-disk global parity scheme name is `cauchy-rs`
- parity-bearing archives must store explicit Cauchy RS scheme metadata
- hardening increases parity budget canonically
- repair never promotes guessed data
- metadata checkpoints either validate exactly or are ignored as damaged
- successful repair restores both damaged data symbols and recomputable damaged Cauchy RS parity symbols
- harden requires a clean archive

## Scaling

The code is global over archive symbols, not individual bytes. Symbol size is the scaling knob.

For large archives, Amber must choose a symbol size such that:

```text
data_symbols + repair_symbols <= 65,536
```

Amber uses one recovery set per archive.

The writer chooses symbol size before emitting records. It uses codec-specific stored-size upper bounds, not observed compression output guesses, because the `GF(2^16)` tag-space requirement must be satisfied before parity generation starts.

The default symbol size is `64 KiB`. Larger archives use larger symbols as needed. If the required symbol size would exceed the on-disk parity payload length field, archive creation fails explicitly.

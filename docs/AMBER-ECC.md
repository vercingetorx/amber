# Amber ECC

Amber's archive ECC scheme is `Cauchy Reed-Solomon ECC`.

Short summary:

- deterministic global Cauchy-form Reed-Solomon code over `GF(2^16)`
- operates over stored archive symbols
- every repair symbol is dense over the protected data-symbol set
- with `R` available repair symbols, repairs any `R` missing or corrupt data symbols
- symbol size is chosen before writing so `data_symbols + repair_symbols <= 65,536`
- large archives scale by increasing symbol size
- supports plaintext and encrypted archives
- uses one canonical ECC policy

The on-disk global parity scheme name is `cauchy-rs`. Parity-bearing archives must store that scheme explicitly in Cauchy RS metadata. Amber treats missing Cauchy RS scheme metadata as malformed rather than guessing it during mutation.

Use [AMBER-ECC-DESIGN.md](./AMBER-ECC-DESIGN.md) for the architecture document.

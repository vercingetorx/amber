# Amber ECC

Amber’s production ECC regime is `AMCF-ECC`:

- Adaptive Multi-Scale Continuous-Field ECC

Short summary:

- deterministic `GF(256)` archive-domain ECC
- built for appendable archives and rewrite-on-commit maintenance
- operates over stored bytes
- supports plaintext and encrypted archives
- uses one canonical policy rather than multiple operator-selectable ECC modes

Tiny groups enforce a minimum total parity floor of `6` rows.

Use [AMBER-ECC-DESIGN.md](./AMBER-ECC-DESIGN.md) for the architecture document.

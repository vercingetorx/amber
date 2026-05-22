# Amber ECC

Amber’s production ECC regime is `AMCF-ECC`:

- Adaptive Multi-Scale Continuous-Field ECC

Short summary:

- deterministic `GF(256)` archive-domain ECC
- built for appendable archives and rewrite-on-commit maintenance
- operates over stored bytes
- supports plaintext and encrypted archives
- uses one canonical policy rather than multiple operator-selectable ECC modes
- uses continuous archive-wide parity geometry rather than fixed repair windows

For standard groups, AMCF combines coverage sweep, local structure, bridge links, neighbor links, dense outer rows, and deterministic coefficient selection. Tiny groups use dense rows and enforce a minimum total parity floor of `6` rows.

The on-disk global parity scheme name is `amcf`. Parity-bearing archives must store that scheme explicitly in AMCF metadata. Amber treats missing AMCF scheme metadata as malformed rather than guessing it during mutation.

Use [AMBER-ECC-DESIGN.md](./AMBER-ECC-DESIGN.md) for the architecture document.

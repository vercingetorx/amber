from __future__ import annotations

import struct
from typing import Dict, List, Tuple

from .hashutil import blake2s_32
from .prng import DeterministicPRNG
from .gf256 import gf_mul


def _derive_attempt_seed(seed_base: bytes, seed_id: int, attempt: int) -> bytes:
    # Deterministically derive a per-attempt seed base so both encoder and
    # decoder explore the same candidate sequence for each seed_id.
    return blake2s_32(seed_base + struct.pack("<I", seed_id) + struct.pack("<I", attempt))


def _precode_degree(n: int) -> int:
    # Small, fixed degree for virtual precode nodes
    if n <= 1:
        return n
    return min(4, n)


def _precode_count(n: int, rho_ppm: int = 10000) -> int:
    # Number of virtual precode nodes; at least 1 for n>=2 to improve mixing
    if n <= 1:
        return 0
    return max(1, (n * rho_ppm) // 1_000_000)


def _sample_precode_row(seed_base: bytes, pre_idx: int, data_indices: List[int]) -> List[Tuple[int, int]]:
    # Deterministically generate a small combination of data for the virtual precode node
    prng = DeterministicPRNG(blake2s_32(seed_base + b"PRE"), pre_idx)
    n = len(data_indices)
    deg = _precode_degree(n)
    seen = set()
    combo: List[Tuple[int, int]] = []
    while len(combo) < deg:
        j = prng.next_uint(n)
        si = data_indices[j]
        if si in seen:
            continue
        seen.add(si)
        c = prng.next_nonzero_byte()
        combo.append((si, c))
    return combo


def _draw_candidate(
    seed_base: bytes, seed_id: int, data_indices: List[int], attempt: int
) -> List[Tuple[int, int]]:
    prng = DeterministicPRNG(_derive_attempt_seed(seed_base, seed_id, attempt), seed_id)
    n = len(data_indices)
    if n == 0:
        return []
    # Raptor-style: fixed small degree band (3..5) regardless of n, capped by n
    base = 3
    span = 3  # degrees in {3,4,5}
    degree = max(1, min(n, base + (prng.next_uint(span))))

    # Virtual precode pool size
    P = _precode_count(n)

    # Enforce pivot coverage: include a deterministic data pivot first
    pivot_idx = seed_id % n
    pivot_symbol = data_indices[pivot_idx]
    coeff_pivot = prng.next_nonzero_byte()

    # Accumulate final data-only combo (expand precode nodes on the fly)
    acc: Dict[int, int] = {pivot_symbol: coeff_pivot}

    while sum(1 for _ in acc) < degree:
        # Draw from extended universe [0 .. n+P-1)
        pick = prng.next_uint(n + P)
        if pick < n:
            sym_index = data_indices[pick]
            c = prng.next_nonzero_byte()
            acc[sym_index] = acc.get(sym_index, 0) ^ c
        else:
            # Expand precode node (pick - n)
            pre_i = pick - n
            pre_combo = _sample_precode_row(seed_base, pre_i, data_indices)
            scale = prng.next_nonzero_byte()
            for si, c in pre_combo:
                acc[si] = acc.get(si, 0) ^ (c if scale == 1 else gf_mul(c, scale))

    # Convert to list excluding zero coefficients
    return [(si, c) for si, c in acc.items() if c]


def _reduce_row_dict(row: Dict[int, int], basis: List[Tuple[int, Dict[int, int]]]) -> Dict[int, int]:
    # Basis is a list of (pivot_col, row_dict) with pivot coeff == 1
    r = dict(row)
    # Iterate basis in pivot order to eliminate
    for pcol, brow in basis:
        coeff = r.get(pcol, 0)
        if not coeff:
            continue
        # r = r - coeff * brow (XOR + GF(256) mul). Since brow[pcol] == 1,
        # we can just XOR coeff into pcol and scale other cols.
        # Work sparsely to keep it compact.
        if coeff == 1:
            # Fast path: XOR rows
            for c, v in brow.items():
                r[c] = r.get(c, 0) ^ v
        else:
            from .gf256 import gf_mul

            for c, v in brow.items():
                r[c] = r.get(c, 0) ^ gf_mul(coeff, v)
        # Clean zero entries to keep sparsity
        if r.get(pcol) == 0:
            r.pop(pcol, None)
    return {c: v for c, v in r.items() if v}


def _add_to_basis(row: Dict[int, int], basis: List[Tuple[int, Dict[int, int]]]) -> bool:
    # Reduce row against basis
    r = _reduce_row_dict(row, basis)
    if not r:
        return False  # dependent
    # Choose pivot as the lowest column with non-zero coeff
    pcol = min(r.keys())
    pivot_coeff = r[pcol]
    if pivot_coeff != 1:
        from .gf256 import gf_inv, gf_mul

        inv = gf_inv(pivot_coeff)
        r = {c: (1 if v == 1 and inv == 1 else gf_mul(v, inv)) for c, v in r.items()}
    basis.append((pcol, r))
    basis.sort(key=lambda x: x[0])
    return True



def sample_rx_combination(seed_base: bytes, seed_id: int, data_indices: List[int]) -> List[Tuple[int, int]]:
    """
    Deterministically samples a random linear combination for an RX parity symbol.

    This function is the core of the RX parity generation. It ensures that
    the generated parity symbols are both random and likely to be linearly
    independent, which is crucial for the decoder to be able to solve for
    lost symbols.

    The process involves:
    1.  **Candidate Generation:** A candidate combination is drawn using a
        deterministic PRNG. This process includes a "virtual precode" to
        improve the properties of the generator, and a pivot to ensure
        all symbols are covered.
    2.  **Rank Verification:** The candidate is checked for linear independence
        against all previously generated combinations for the same ECC group.
        This is done by attempting to add the candidate to a basis of the
        previously accepted combinations. If it's dependent, a new candidate
        is generated and the process is repeated.

    This ensures that the encoder and decoder will always agree on the same
    set of combinations, which is essential for successful recovery.

    Properties:
    - Uniform: small fixed degree band ({3,4,5}) with virtual precode expansion
    - Pivot coverage: always includes column at index (seed_id mod n)
    - Rank-verified: if the first candidate is dependent w.r.t. previously
      accepted rows (seed_id' < seed_id), keep trying new candidates by
      deriving a fresh per-attempt seed. Attempts are capped, but both encoder
      and decoder reproduce the same sequence, so determinism holds.
    """
    # Ensure stable column ordering
    data_indices = sorted(data_indices)
    n = len(data_indices)
    if n == 0:
        return []

    # Build basis of previously accepted rows up to seed_id
    basis = []  # type: List[Tuple[int, Dict[int, int]]]
    # Recursively reconstruct prefix rows without reusing caller state; acceptable sizes.
    for sid in range(seed_id):
        combo_prev = _draw_candidate(seed_base, sid, data_indices, 0)
        # Find an acceptable candidate for previous rows by testing attempts
        attempt = 0
        while True:
            combo_prev = _draw_candidate(seed_base, sid, data_indices, attempt)
            # Convert to pos map and test add
            pos_map: Dict[int, int] = {}
            for sym_index, coeff in combo_prev:
                pos = data_indices.index(sym_index)
                pos_map[pos] = pos_map.get(pos, 0) ^ coeff
            if _add_to_basis(pos_map, basis):
                break
            attempt += 1
            if attempt > 8:
                # Accept dependent after attempts cap to avoid livelock; still deterministic
                _add_to_basis(pos_map, basis)
                break

    # Now find a candidate for the requested seed_id
    attempt = 0
    while True:
        combo = _draw_candidate(seed_base, seed_id, data_indices, attempt)
        pos_map: Dict[int, int] = {}
        for sym_index, coeff in combo:
            pos = data_indices.index(sym_index)
            pos_map[pos] = pos_map.get(pos, 0) ^ coeff
        # Check independence without mutating basis
        reduced = _reduce_row_dict(pos_map, basis)
        if reduced:
            return combo
        attempt += 1
        if attempt > 8:
            # Give up and return last candidate to remain deterministic
            return combo

from __future__ import annotations

import os
import struct
from typing import Dict, List, Set, Tuple
import itertools
import zlib

from .hashutil import blake2s_16
from .errors import AmberError
from .gf256 import gf_mul, gf_inv, gf_mul_bytes, gf_add_bytes
from .records import read_record_at, _REC_HDR_STRUCT, parse_chunk_header_ext
from .constants import RTYPE_CHUNK, REC_SYNC
from .codec import Codec


class ECCRepairResult:
    """Book-keeping container describing what the repair pass managed to fix."""
    def __init__(self):
        self.lrp_repaired: List[int] = []
        self.rx_repaired: List[int] = []
        self.remaining_corrupted: List[int] = []


def detect_corrupted_symbols(reader, file_handle) -> Set[int]:
    """
    Identifies corrupted symbols by performing a multi-level integrity check.

    1.  **Symbol Tag Check:** Each symbol's stored tag is compared against a fresh
        hash of its payload. This is the primary and most granular check.
    2.  **Chunk Integrity Check:** For data symbols, the integrity of the entire
        chunk record is also verified. This helps detect corruption in the chunk
        header or other metadata that wouldn't be caught by the symbol tag alone.

    Returns:
        A set of symbol indices corresponding to corrupted symbols.
    """
    corrupted: Set[int] = set()
    chunk_symbols: Dict[int, List[int]] = {}
    for sym in reader.symbols:
        if sym.is_parity:
            continue
        record_offset = sym.record_offset
        if record_offset is None:
            continue
        chunk_symbols.setdefault(int(record_offset), []).append(sym.symbol_index)
    chunk_verification: Dict[int, bool] = {}
    for sym in reader.symbols:
        if sym.length == 0:
            continue
        payload, plain_len = _load_symbol_data(reader, file_handle, sym)
        if payload is None:
            corrupted.add(sym.symbol_index)
            continue
        if plain_len <= 0:
            corrupted.add(sym.symbol_index)
            continue
        if blake2s_16(payload[:plain_len]) != sym.tag16:
            corrupted.add(sym.symbol_index)
            continue
        if not sym.is_parity:
            record_offset = sym.record_offset
            if record_offset is not None:
                status = chunk_verification.get(int(record_offset))
                if status is None:
                    status = _verify_chunk_integrity(reader, file_handle, int(record_offset))
                    chunk_verification[int(record_offset)] = status
                if not status:
                    impacted = chunk_symbols.get(int(record_offset), [])
                    if impacted:
                        corrupted.add(impacted[0])
    return corrupted


def _verify_chunk_integrity(reader, fh, record_offset: int) -> bool:
    """Re-read a chunk record and ensure its payload still matches the stored tag."""
    decryptor = reader.decryptor
    try:
        rtype, _rflags, hdr_ext, payload = read_record_at(fh, record_offset, decryptor=decryptor)
    except (AmberError, OSError, ValueError, RuntimeError):
        return False
    if rtype != RTYPE_CHUNK:
        return False
    try:
        entry_id, chunk_index, ulen, codec_id, _flags, tag16, _aux = parse_chunk_header_ext(hdr_ext)
    except ValueError:
        return False
    codec = Codec(codec_id)
    try:
        raw = codec.decompress(payload)
    except (RuntimeError, ValueError, zlib.error):
        return False
    return blake2s_16(raw) == tag16


def repair_archive(reader, path: str) -> ECCRepairResult:
    result = ECCRepairResult()
    with open(path, "rb+") as fh:
        corrupted = detect_corrupted_symbols(reader, fh)
        if not corrupted:
            result.remaining_corrupted = []
            return result
        lrp_fixed = _repair_lrp(reader, fh, corrupted)
        result.lrp_repaired = lrp_fixed
        corrupted.difference_update(lrp_fixed)
        if corrupted and reader.rx_parities:
            rx_fixed = _repair_rx(reader, fh, corrupted)
            result.rx_repaired = rx_fixed
            corrupted.difference_update(rx_fixed)
        result.remaining_corrupted = sorted(corrupted)
        fh.flush()
        os.fsync(fh.fileno())
    return result


def _repair_lrp(reader, fh, corrupted: Set[int]) -> List[int]:
    """Repair data/parity symbols that belong to single-erasure LRP stripes."""
    repaired: List[int] = []
    for stripe in reader.stripes:
        targets = [idx for idx in stripe.data_symbols + [stripe.parity_symbol] if idx in corrupted]
        if not targets:
            continue
        if len(targets) == 1 and stripe.parity_symbol not in targets:
            sym_idx = targets[0]
            if _recover_data_symbol(reader, fh, stripe, sym_idx):
                repaired.append(sym_idx)
        elif len(targets) == 1 and stripe.parity_symbol in targets:
            if _rebuild_parity_symbol(reader, fh, stripe):
                repaired.append(stripe.parity_symbol)
    return repaired


def _repair_rx(reader, fh, corrupted: Set[int]) -> List[int]:
    """
    Attempts to repair corrupted data symbols using the RX error correction scheme.

    This function implements a two-stage decoding process:

    1.  **Peeling Decoder:** An efficient iterative process that solves for unknowns
        in equations with only one missing variable (degree 1). As symbols are
        solved, they are substituted into other equations, often creating new
        degree-1 equations. This process continues until no more symbols can be
        solved this way.

    2.  **Sparse Elimination Fallback:** If the peeling decoder cannot solve all
        unknowns, a residual system of linear equations remains. If this system
        is small enough (e.g., <= 32 variables), this function will attempt to
        solve it using Gaussian elimination.

    The combination of these two methods provides a good balance between
    performance and capability, as the peeling decoder is very fast for the
    common case, and the fallback can handle more complex loss patterns.
    """
    # We only solve for data symbols. Parity symbols are not directly recovered
    # by this process, but are used to form the equations.
    unknowns = sorted(idx for idx in corrupted if not reader.symbols[idx].is_parity)
    if not unknowns:
        return []
    symbol_size = reader.symbol_size
    unknown_pos = {idx: pos for pos, idx in enumerate(unknowns)}
    # Build per-group data index sets keyed by seed_base; scope each parity to its group
    group_data_indices: Dict[bytes, List[int]] = {}
    if reader.index:
        groups = reader.index.get("ecc_groups", [])  # type: ignore
        for g in groups:
            rx = g.get("rx") if isinstance(g, dict) else None
            if not rx:
                continue
            seed_base = rx.get("seed_base", b"")
            di = [
                int(s.get("symbol_index"))
                for s in g.get("symbols", [])
                if not bool(s.get("is_parity", False))
            ]
            if di:
                sorted_di = sorted(di)
                base_key = bytes(seed_base) if isinstance(seed_base, (bytes, bytearray)) else b""
                if base_key:
                    group_data_indices[base_key] = sorted_di
                for item in rx.get("parity", []):
                    sb_item = item.get("seed_base") if isinstance(item, dict) else None
                    if isinstance(sb_item, (bytes, bytearray)) and sb_item:
                        group_data_indices[sb_item] = sorted_di

    # Build a system of linear equations. Each equation is formed from a valid
    # (uncorrupted) parity symbol. The equation is of the form:
    #
    #   c1*x1 + c2*x2 + ... = P - (c_known * x_known + ...)
    #
    # where x_i are the unknown (corrupted) symbols, and P is the parity symbol.
    # The right-hand side (RHS) is adjusted by subtracting the contributions
    # of all known (uncorrupted) symbols.
    equations = []  # list of dict(pos->coeff), rhs bytearray
    for parity in reader.rx_parities:
        if parity.symbol_index in corrupted:
            continue  # skip corrupted parity
        from .rx import sample_rx_combination
        sbase = parity.seed_base
        di = group_data_indices.get(sbase)
        if not di:
            raise ValueError("RX parity references unknown seed_base")
        combo = sample_rx_combination(sbase, parity.seed_id, di)
        parity_symbol = reader.symbols[parity.symbol_index]
        rhs_bytes = _read_symbol(reader, fh, parity_symbol)
        if rhs_bytes is None:
            continue
        rhs = bytearray(rhs_bytes)
        coeffs: Dict[int, int] = {}
        skip_eq = False
        has_unknown = False
        for sym_index, coeff in combo:
            symbol = reader.symbols[sym_index]
            data = _read_symbol(reader, fh, symbol)
            if data is None:
                skip_eq = True
                break
            if sym_index in corrupted:
                pos = unknown_pos.get(sym_index)
                if pos is None:
                    continue
                # Combine coefficients if symbol appears twice (shouldn't, but guard)
                prev = coeffs.get(pos, 0)
                coeffs[pos] = prev ^ coeff
                has_unknown = True
            else:
                contrib = gf_mul_bytes(data, coeff)
                gf_add_bytes(rhs, contrib)
        if skip_eq or not has_unknown:
            continue
        equations.append((coeffs, rhs))

    # Incorporate LRP stripe equations (XOR parity) when parity symbol is intact.
    for stripe in reader.stripes:
        unknown_targets = [idx for idx in stripe.data_symbols if idx in corrupted]
        if not unknown_targets:
            continue
        parity_idx = stripe.parity_symbol
        if parity_idx in corrupted:
            continue
        parity_symbol = reader.symbols[parity_idx]
        parity_payload = _read_symbol(reader, fh, parity_symbol)
        if parity_payload is None:
            continue
        rhs = bytearray(parity_payload)
        skip_eq = False
        for data_idx in stripe.data_symbols:
            if data_idx in corrupted:
                continue
            sym = reader.symbols[data_idx]
            data_bytes = _read_symbol(reader, fh, sym)
            if data_bytes is None:
                skip_eq = True
                break
            gf_add_bytes(rhs, data_bytes)
        if skip_eq:
            continue
        coeffs: Dict[int, int] = {}
        for sym_idx in unknown_targets:
            pos = unknown_pos.get(sym_idx)
            if pos is None:
                continue
            coeffs[pos] = coeffs.get(pos, 0) ^ 1  # XOR parity => coefficient 1
        if not coeffs:
            continue
        equations.append((coeffs, rhs))

    if not equations:
        return []

    # --- Peeling Decoder ---
    #
    # This is the first and most efficient stage of the recovery process.
    # It iteratively solves equations that have only one unknown variable.
    solutions: Dict[int, bytes] = {}
    # Build adjacency: for each unknown pos, which equations and coefficients
    var_to_eqs: Dict[int, List[int]] = {}
    for i, (coeffs, _rhs) in enumerate(equations):
        for pos, c in coeffs.items():
            var_to_eqs.setdefault(pos, []).append(i)

    # Initialize queue with equations of degree 1
    from collections import deque

    def eq_degree(idx: int) -> int:
        return sum(1 for _ in equations[idx][0].items() if _[1] != 0)

    q = deque([i for i in range(len(equations)) if eq_degree(i) == 1])

    while q:
        ei = q.popleft()
        coeffs, rhs = equations[ei]
        # Find the single unknown
        singles = [(pos, c) for pos, c in coeffs.items() if c != 0]
        if len(singles) != 1:
            continue
        pos, c = singles[0]
        if pos in solutions:
            continue
        inv = gf_inv(c)
        value = gf_mul_bytes(bytes(rhs), inv)
        solutions[pos] = bytes(value)
        # Substitute into all other equations
        if pos in var_to_eqs:
            impacted = list(var_to_eqs[pos])
            for ej in impacted:
                if ej == ei:
                    continue
                cdict, rr = equations[ej]
                cc = cdict.get(pos, 0)
                if cc:
                    gf_add_bytes(rr, gf_mul_bytes(value, cc))
                    cdict[pos] = 0
                    # If this equation becomes degree 1, enqueue
                    deg = sum(1 for _ in cdict.values() if _ != 0)
                    if deg == 1:
                        q.append(ej)

    # If all solved, write back
    repaired: List[int] = []
    if len(solutions) == len(unknowns):
        for pos, data_bytes in solutions.items():
            sym_index = unknowns[pos]
            symbol = reader.symbols[sym_index]
            actual = data_bytes[: symbol.length]
            if blake2s_16(actual) != symbol.tag16:
                continue
            fh.seek(symbol.offset)
            fh.write(actual)
            repaired.append(sym_index)
        return repaired

    # --- Gaussian Elimination Fallback ---
    #
    # If the peeling decoder fails to solve all unknowns, we are left with a
    # residual system of equations. If this system is small enough, we can
    # solve it using Gaussian elimination.
    residual_vars = [pos for pos in range(len(unknowns)) if pos not in solutions]
    if not residual_vars:
        return repaired
    if len(residual_vars) > 32:
        # Avoid heavy elimination on large systems; return what we have
        return repaired

    # Build reduced system A*x = b for residuals
    var_index = {pos: i for i, pos in enumerate(residual_vars)}
    A: List[List[int]] = []
    B: List[bytearray] = []
    for coeffs, rhs in equations:
        row = [0] * len(residual_vars)
        nz = 0
        for pos, c in coeffs.items():
            if c and pos in var_index:
                row[var_index[pos]] ^= c
                nz += 1
        if nz:
            # Substitute known solutions into RHS
            if solutions:
                for spos, sval in solutions.items():
                    cc = coeffs.get(spos, 0)
                    if cc:
                        gf_add_bytes(rhs, gf_mul_bytes(sval, cc))
            A.append(row)
            B.append(bytearray(rhs))
    # Attempt Gaussian elimination
    m = len(A)
    nvars = len(residual_vars)
    r = 0
    pivots: List[int] = [-1] * nvars
    for c in range(nvars):
        # Find pivot row with non-zero in column c
        pivot = -1
        for i in range(r, m):
            if A[i][c] != 0:
                pivot = i
                break
        if pivot == -1:
            continue
        if pivot != r:
            A[r], A[pivot] = A[pivot], A[r]
            B[r], B[pivot] = B[pivot], B[r]
        inv = gf_inv(A[r][c])
        # Normalize row r
        for j in range(c, nvars):
            if A[r][j]:
                A[r][j] = gf_mul(A[r][j], inv)
        B[r] = bytearray(gf_mul_bytes(B[r], 1 if inv == 1 else inv))
        # Eliminate other rows
        for i in range(m):
            if i == r:
                continue
            factor = A[i][c]
            if factor:
                # Row i = Row i - factor * Row r
                for j in range(c, nvars):
                    if A[r][j]:
                        A[i][j] ^= gf_mul(A[r][j], factor)
                gf_add_bytes(B[i], gf_mul_bytes(B[r], factor))
        pivots[c] = r
        r += 1
        if r == m:
            break
    # Back-substitution to extract solutions
    X: List[bytes | None] = [None] * nvars
    for c in range(nvars - 1, -1, -1):
        pr = pivots[c]
        if pr == -1:
            continue
        rhs = bytearray(B[pr])
        # Subtract contributions of already solved variables to the right
        for k in range(c + 1, nvars):
            if X[k] is None:
                continue
            coeff = A[pr][k]
            if coeff:
                gf_add_bytes(rhs, gf_mul_bytes(X[k], coeff))
        # Pivot coefficient is 1 after normalization
        X[c] = bytes(rhs)
    # Map back solved residuals into global solutions
    for c in range(nvars):
        if X[c] is None:
            continue
        pos = residual_vars[c]
        solutions[pos] = X[c]

    # Write back any newly solved ones
    for pos in list(solutions.keys()):
        sym_index = unknowns[pos]
        if sym_index not in corrupted:
            continue
        symbol = reader.symbols[sym_index]
        actual = solutions[pos][: symbol.length]
        if blake2s_16(actual) != symbol.tag16:
            continue
        fh.seek(symbol.offset)
        fh.write(actual)
        repaired.append(sym_index)
    return sorted(set(repaired))


def _solve_linear_system(equations: List[Tuple[List[int], bytearray]], unknown_count: int) -> List[bytes | None]:
    """
    Solves a system of linear equations using a brute-force approach.

    This function is a fallback solver and is not intended for large systems.
    It works by trying all combinations of equations to find a solvable
    (invertible) matrix. This is computationally expensive and only suitable
    for very small systems. The main `_repair_rx` function uses a more
    efficient peeling decoder and a targeted Gaussian elimination fallback.
    """
    if unknown_count == 0:
        return []
    eq_count = len(equations)
    solutions: List[bytes | None] = [None] * unknown_count
    if eq_count < unknown_count:
        return solutions
    for combo in itertools.combinations(range(eq_count), unknown_count):
        matrix = [[equations[i][0][j] for j in range(unknown_count)] for i in combo]
        inverse = _invert_matrix(matrix)
        if inverse is None:
            continue
        rhs_list = [equations[i][1] for i in combo]
        sols = _apply_inverse(inverse, rhs_list)
        if sols:
            return sols
    return solutions


def _invert_matrix(matrix: List[List[int]]) -> List[List[int]] | None:
    """
    Inverts a matrix in GF(2^8) using Gaussian elimination.

    This function augments the input matrix with the identity matrix and then
    performs row operations to transform the input matrix into the identity
    matrix. The resulting augmented part is the inverse of the original matrix.
    """
    n = len(matrix)
    aug = []
    for i in range(n):
        row = matrix[i][:]
        if len(row) != n:
            return None
        identity = [0] * n
        identity[i] = 1
        aug.append(row + identity)
    for col in range(n):
        pivot = None
        for r in range(col, n):
            if aug[r][col] != 0:
                pivot = r
                break
        if pivot is None:
            return None
        if pivot != col:
            aug[col], aug[pivot] = aug[pivot], aug[col]
        pivot_coeff = aug[col][col]
        inv = gf_inv(pivot_coeff)
        for c in range(2 * n):
            aug[col][c] = gf_mul(aug[col][c], inv)
        for r in range(n):
            if r == col:
                continue
            factor = aug[r][col]
            if factor:
                for c in range(2 * n):
                    aug[r][c] ^= gf_mul(factor, aug[col][c])
    inverse = []
    for row in aug:
        inverse.append(row[n:])
    return inverse


def _apply_inverse(inverse: List[List[int]], rhs_list: List[bytearray]) -> List[bytes | None]:
    n = len(inverse)
    if not rhs_list:
        return [None] * n
    symbol_size = len(rhs_list[0])
    solutions: List[bytes | None] = [bytearray(symbol_size) for _ in range(n)]
    for i in range(n):
        for j in range(n):
            coeff = inverse[i][j]
            if coeff:
                contrib = gf_mul_bytes(bytes(rhs_list[j]), coeff)
                gf_add_bytes(solutions[i], contrib)
    return [bytes(sol) for sol in solutions]


# RX sampling is centralized in amber.rx.sample_rx_combination


def _recover_data_symbol(reader, fh, stripe, missing_idx: int) -> bool:
    symbol = reader.symbols[missing_idx]
    parity = reader.symbols[stripe.parity_symbol]
    parity_buf = _read_symbol(reader, fh, parity)
    if parity_buf is None:
        return False
    acc = bytearray(parity_buf)
    for idx in stripe.data_symbols:
        if idx == missing_idx:
            continue
        other = reader.symbols[idx]
        other_buf = _read_symbol(reader, fh, other)
        if other_buf is None:
            return False
        for i in range(symbol.length):
            acc[i] ^= other_buf[i]
    data = bytes(acc[: symbol.length])
    original_bytes = _read_symbol(reader, fh, symbol)
    if original_bytes is None:
        return False
    fh.seek(symbol.offset)
    fh.write(data)
    fh.flush()
    os.fsync(fh.fileno())
    record_offset = symbol.record_offset
    if record_offset is None or not _verify_chunk_integrity(reader, fh, int(record_offset)):
        # restore original bytes if verification fails
        fh.seek(symbol.offset)
        fh.write(original_bytes[: symbol.length])
        fh.flush()
        os.fsync(fh.fileno())
        return False
    return True


def _rebuild_parity_symbol(reader, fh, stripe) -> bool:
    parity = reader.symbols[stripe.parity_symbol]
    buf = bytearray(reader.symbol_size)
    for idx in stripe.data_symbols:
        sym = reader.symbols[idx]
        sym_buf = _read_symbol(reader, fh, sym)
        if sym_buf is None:
            return False
        for i in range(sym.length):
            buf[i] ^= sym_buf[i]
    plaintext = bytes(buf[: reader.symbol_size])
    hash_input = plaintext[: reader.symbol_size]
    encryptor = reader.decryptor
    if encryptor is not None and parity.is_parity:
        record_offset = parity.record_offset
        if record_offset is None:
            return False
        header_bytes = _read_record_header_bytes(fh, record_offset)
        if header_bytes is None:
            return False
        ciphertext = encryptor.encrypt(header_bytes, plaintext, nonce_material=struct.pack("<Q", record_offset))
        if len(ciphertext) != parity.length:
            # Truncate or pad to expected stored length to avoid partial writes
            if len(ciphertext) < parity.length:
                ciphertext = ciphertext + b"\x00" * (parity.length - len(ciphertext))
            else:
                ciphertext = ciphertext[: parity.length]
        fh.seek(parity.offset)
        fh.write(ciphertext)
    else:
        fh.seek(parity.offset)
        fh.write(plaintext[: parity.length])
    fh.flush()
    os.fsync(fh.fileno())
    return blake2s_16(hash_input) == parity.tag16


def _load_symbol_data(reader, fh, symbol) -> Tuple[bytes | None, int]:
    decryptor = reader.decryptor
    if decryptor is not None and symbol.is_parity:
        record_offset = symbol.record_offset
        if record_offset is None:
            return None, 0
        try:
            rtype, _rflags, _hdr_ext, payload = read_record_at(fh, record_offset, decryptor=decryptor)
        except (AmberError, OSError, ValueError, RuntimeError):
            return None, 0
        if rtype != RTYPE_CHUNK:
            return None, 0
        plain_len = min(len(payload), reader.symbol_size)
        buf = bytearray(reader.symbol_size)
        buf[:plain_len] = payload[:plain_len]
        return bytes(buf), plain_len
    fh.seek(symbol.offset)
    data = fh.read(symbol.length)
    if len(data) != symbol.length:
        return None, 0
    buf = bytearray(reader.symbol_size)
    buf[: symbol.length] = data
    return bytes(buf), symbol.length


def _read_record_header_bytes(fh, record_offset: int) -> bytes | None:
    fh.seek(record_offset)
    fixed = fh.read(_REC_HDR_STRUCT.size)
    if len(fixed) != _REC_HDR_STRUCT.size:
        return None
    sync, _rtype, _rflags, header_len, _payload_len, _hdr_crc, _reserved = _REC_HDR_STRUCT.unpack(fixed)
    if sync != REC_SYNC:
        return None
    header_ext = fh.read(header_len) if header_len else b""
    return fixed + header_ext


def _read_symbol(reader, fh, symbol) -> bytes | None:
    payload, _plain_len = _load_symbol_data(reader, fh, symbol)
    return payload

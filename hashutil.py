from __future__ import annotations

import hashlib


def blake2s_32(data: bytes) -> bytes:
    # Use hashlib.blake2s to provide a 32-byte digest without extra deps.
    return hashlib.blake2s(data, digest_size=32).digest()


def blake2s_16(data: bytes) -> bytes:
    return hashlib.blake2s(data, digest_size=16).digest()


def merkle_leaf_from_chunk_tag(tag16: bytes) -> bytes:
    """Derive a 32-byte leaf from a 16-byte chunk tag.

    We domain-separate to avoid confusion with raw chunk hashes.
    """
    return blake2s_32(b"SS_LEAF\x00" + tag16)


def merkle_parent(left32: bytes, right32: bytes) -> bytes:
    return blake2s_32(b"SS_NODE\x00" + left32 + right32)

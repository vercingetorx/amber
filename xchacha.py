from __future__ import annotations

"""Lightweight XChaCha20-Poly1305 construction backed by PyCryptodomex.

This module derives the subkey via HChaCha20 and then delegates the final
12-byte ChaCha20-Poly1305 operation to ``Cryptodome.Cipher.ChaCha20_Poly1305``.
It mirrors libsodium's XChaCha20-Poly1305 (IETF) behaviour and exists so the
rest of the archive stack can migrate away from fixed 12-byte nonces without
pulling in an additional dependency.
"""

from typing import Tuple

try:  # pragma: no cover - optional dependency at runtime
    from Cryptodome.Cipher import ChaCha20_Poly1305  # type: ignore
    _HAS_CRYPTODOME = True
except ImportError:  # pragma: no cover - fallback
    ChaCha20_Poly1305 = None  # type: ignore
    _HAS_CRYPTODOME = False


_CHACHA_CONST = (
    0x61707865,
    0x3320646E,
    0x79622D32,
    0x6B206574,
)
_TAG_SIZE = 16
_KEY_SIZE = 32
_NONCE_SIZE = 24


def _rotl32(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def _hchacha20(key: bytes, nonce: bytes) -> bytes:
    if len(key) != _KEY_SIZE:
        raise ValueError("HChaCha20 expects 32-byte key")
    if len(nonce) != 16:
        raise ValueError("HChaCha20 expects 16-byte nonce")

    state = [
        _CHACHA_CONST[0],
        _CHACHA_CONST[1],
        _CHACHA_CONST[2],
        _CHACHA_CONST[3],
    ]
    state.extend(int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4))
    state.extend(int.from_bytes(nonce[i : i + 4], "little") for i in range(0, 16, 4))

    for _ in range(10):  # 20 rounds (10 double rounds)
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)

    output_words = [
        state[0],
        state[5],
        state[10],
        state[15],
        state[6],
        state[7],
        state[8],
        state[9],
    ]
    return b"".join(word.to_bytes(4, "little") for word in output_words)


def _ensure_backend() -> None:
    if not _HAS_CRYPTODOME:
        raise RuntimeError("PyCryptodomex is required for XChaCha20-Poly1305 support")


class XChaCha20Poly1305:
    """Minimal XChaCha20-Poly1305 helper backed by PyCryptodomex."""

    def __init__(self, key: bytes):
        if len(key) != _KEY_SIZE:
            raise ValueError("Key must be 32 bytes for XChaCha20-Poly1305")
        _ensure_backend()
        self._key = key

    def encrypt(self, nonce: bytes, plaintext: bytes, *, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
        """Encrypt and authenticate ``plaintext`` with the provided 24-byte ``nonce``.

        Returns (ciphertext, tag).
        """
        if len(nonce) != _NONCE_SIZE:
            raise ValueError("Nonce must be 24 bytes for XChaCha20-Poly1305")
        subkey = _hchacha20(self._key, nonce[:16])
        chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:]
        cipher = ChaCha20_Poly1305.new(key=subkey, nonce=chacha_nonce)
        if associated_data:
            cipher.update(associated_data)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, *, associated_data: bytes = b"") -> bytes:
        """Verify and decrypt with the given 24-byte ``nonce`` and 16-byte ``tag``."""
        if len(nonce) != _NONCE_SIZE:
            raise ValueError("Nonce must be 24 bytes for XChaCha20-Poly1305")
        if len(tag) != _TAG_SIZE:
            raise ValueError("Authentication tag must be 16 bytes")
        subkey = _hchacha20(self._key, nonce[:16])
        chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:]
        cipher = ChaCha20_Poly1305.new(key=subkey, nonce=chacha_nonce)
        if associated_data:
            cipher.update(associated_data)
        return cipher.decrypt_and_verify(ciphertext, tag)


__all__ = [
    "XChaCha20Poly1305",
    "_HAS_CRYPTODOME",
]

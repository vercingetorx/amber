from __future__ import annotations

import os
from dataclasses import dataclass
import hmac
import hashlib

try:  # pragma: no cover - availability depends on environment
    from argon2.low_level import Type as _ArgonType, hash_secret_raw as _argon_hash  # type: ignore
    _HAS_ARGON2 = True
except ImportError:  # pragma: no cover - graceful fallback
    _ArgonType = None  # type: ignore
    _argon_hash = None  # type: ignore
    _HAS_ARGON2 = False

from .xchacha import XChaCha20Poly1305, _HAS_CRYPTODOME


NONCE_SIZE = 24
TAG_SIZE = 16
KEY_SIZE = 32
SALT_SIZE = 16

# Fixed Argon2id parameters for archive encryption (chosen for strong defaults)
ARGON_TIME_COST = 3
ARGON_MEMORY_COST_KIB = 256 * 1024  # 256 MiB
ARGON_PARALLELISM = 4


@dataclass
class EncryptionParams:
    salt: bytes
    time_cost: int
    memory_cost_kib: int
    parallelism: int


class EncryptionContext:
    def __init__(self, key: bytes, params: EncryptionParams):
        self.key = key
        self.params = params
        self._cipher = XChaCha20Poly1305(key)

    @classmethod
    def create(cls, password: str) -> "EncryptionContext":
        if not (_HAS_CRYPTO and _argon_hash is not None and _ArgonType is not None):
            raise RuntimeError("argon2-cffi and PyCryptodomex are required for encryption support")
        salt = os.urandom(SALT_SIZE)
        key = _argon_hash(
            password.encode("utf-8"),
            salt,
            time_cost=ARGON_TIME_COST,
            memory_cost=ARGON_MEMORY_COST_KIB,
            parallelism=ARGON_PARALLELISM,
            hash_len=KEY_SIZE,
            type=_ArgonType.ID,
        )
        return cls(
            key,
            EncryptionParams(
                salt=salt,
                time_cost=ARGON_TIME_COST,
                memory_cost_kib=ARGON_MEMORY_COST_KIB,
                parallelism=ARGON_PARALLELISM,
            ),
        )

    @classmethod
    def from_params(cls, password: str, params: EncryptionParams) -> "EncryptionContext":
        if not (_HAS_CRYPTO and _argon_hash is not None and _ArgonType is not None):
            raise RuntimeError("argon2-cffi and PyCryptodomex are required for encryption support")
        if (
            params.time_cost != ARGON_TIME_COST
            or params.memory_cost_kib != ARGON_MEMORY_COST_KIB
            or params.parallelism != ARGON_PARALLELISM
        ):
            raise ValueError("Unsupported Argon2 parameters in archive")
        key = _argon_hash(
            password.encode("utf-8"),
            params.salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost_kib,
            parallelism=params.parallelism,
            hash_len=KEY_SIZE,
            type=_ArgonType.ID,
        )
        return cls(key, params)

    def _derive_nonce(self, nonce_material: bytes) -> bytes:
        return hmac.new(self.key, b"AMBER_REC_NONCE" + nonce_material, hashlib.sha512).digest()[:NONCE_SIZE]

    def encrypt(self, aad: bytes, plaintext: bytes, *, nonce_material: bytes) -> bytes:
        nonce = self._derive_nonce(nonce_material)
        ciphertext, tag = self._cipher.encrypt(nonce, plaintext, associated_data=aad)
        return nonce + ciphertext + tag

    def decrypt(self, aad: bytes, payload: bytes) -> bytes:
        if len(payload) < NONCE_SIZE + TAG_SIZE:
            raise ValueError("Encrypted payload too short")
        nonce = payload[:NONCE_SIZE]
        tag = payload[-TAG_SIZE:]
        ciphertext = payload[NONCE_SIZE:-TAG_SIZE]
        return self._cipher.decrypt(nonce, ciphertext, tag, associated_data=aad)

    def overhead(self) -> int:
        return NONCE_SIZE + TAG_SIZE

    def export_params(self) -> EncryptionParams:
        return self.params
_HAS_CRYPTO = bool(_HAS_ARGON2 and _HAS_CRYPTODOME)

from __future__ import annotations

import hashlib


class DeterministicPRNG:
    """Deterministic pseudo-random byte generator based on BLAKE2b."""

    def __init__(self, seed_base: bytes, seed_id: int):
        self.seed_base = seed_base
        self.seed_id = seed_id
        self.counter = 0
        self.buffer = b""
        self.pos = 0

    def _refill(self):
        material = self.seed_base + self.seed_id.to_bytes(8, "little") + self.counter.to_bytes(4, "little")
        self.buffer = hashlib.blake2b(material, digest_size=32).digest()
        self.counter += 1
        self.pos = 0

    def next_byte(self) -> int:
        if self.pos >= len(self.buffer):
            self._refill()
        b = self.buffer[self.pos]
        self.pos += 1
        return b

    def next_uint(self, modulus: int) -> int:
        if modulus <= 0:
            return 0
        # 64-bit rejection sampling for all moduli > 0
        while True:
            v = 0
            for _ in range(8):
                v = (v << 8) | self.next_byte()
            limit = (1 << 64) - ((1 << 64) % modulus)
            if v < limit:
                return v % modulus

    def next_nonzero_byte(self) -> int:
        while True:
            b = self.next_byte()
            if b != 0:
                return b

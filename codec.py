from __future__ import annotations

from typing import Optional

from .constants import CODEC_NONE, CODEC_ZSTD, CODEC_DEFLATE, CODEC_LRP_PARITY, CODEC_RX_PARITY

import zlib

_HAS_ZSTD = False
_zstd_mod = None
_ZstdError = RuntimeError
try:  # Prefer stdlib zstd when available (Python 3.14+ TBD); else try third-party if installed
    import zstandard as _zstd_mod  # type: ignore
    from zstandard import ZstdError as _ZstdError  # type: ignore
    _HAS_ZSTD = True
except ImportError:
    try:
        import zstd as _zstd_mod  # type: ignore
        from zstd import ZstdError as _ZstdError  # type: ignore
        _HAS_ZSTD = True
    except ImportError:
        _zstd_mod = None
        _HAS_ZSTD = False


class Codec:
    def __init__(self, codec_id: int, level: Optional[int] = None):
        self.codec_id = codec_id
        self.level = level

    def compress(self, data: bytes) -> bytes:
        if self.codec_id == CODEC_NONE:
            return data
        # Parity payloads are already final bytes; no compression
        if self.codec_id in (CODEC_LRP_PARITY, CODEC_RX_PARITY):
            return data
        # Deflate via zlib; zstd via stdlib or optional zstandard module
        if self.codec_id == CODEC_DEFLATE:
            return zlib.compress(data, self.level if self.level is not None else 6)
        if self.codec_id == CODEC_ZSTD:
            if not (_HAS_ZSTD and _zstd_mod is not None):
                raise RuntimeError("zstd codec selected but zstd module is not available")
            try:
                c = _zstd_mod.ZstdCompressor(level=self.level if self.level is not None else 3)
                return c.compress(data)
            except _ZstdError as e:
                raise RuntimeError(f"zstd compression failed: {e}")
        # Unknown/unsupported codec: fail fast
        raise RuntimeError(f"unsupported codec id: {self.codec_id}")

    def decompress(self, data: bytes) -> bytes:
        if self.codec_id == CODEC_NONE:
            return data
        # Parity payloads are not compressed
        if self.codec_id in (CODEC_LRP_PARITY, CODEC_RX_PARITY):
            return data
        if self.codec_id == CODEC_DEFLATE:
            return zlib.decompress(data)
        if self.codec_id == CODEC_ZSTD:
            if not (_HAS_ZSTD and _zstd_mod is not None):
                raise RuntimeError("zstd codec not available to decompress")
            try:
                d = _zstd_mod.ZstdDecompressor()
                return d.decompress(data)
            except _ZstdError as e:
                raise RuntimeError(f"zstd decompression failed: {e}")
        # Unknown/unsupported codec: fail fast
        raise RuntimeError(f"unsupported codec id: {self.codec_id}")

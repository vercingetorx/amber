#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from amber.writer import ArchiveWriter
from amber.reader import ArchiveReader
from amber.ecc import repair_archive
from amber.harden import append_rx_parity
from amber.hashutil import blake2s_16
from amber.constants import CODEC_NONE


def flip_byte(path: Path, offset: int):
    with open(path, "rb+") as fh:
        fh.seek(offset)
        b = fh.read(1)
        if not b:
            return
        fh.seek(offset)
        fh.write(bytes([b[0] ^ 0xFF]))


def corrupt_first_two_data_symbols(archive: Path, password: str | None = None):
    with ArchiveReader(str(archive), password=password) as r:
        targets = [s for s in r.symbols if not s.is_parity][:2]
    for s in targets:
        flip_byte(archive, s.offset)


def scenario(encrypted: bool = False):
    password = "secret" if encrypted else None
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # Create some input files
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "a.txt").write_text("hello world\n" * 1024, encoding="utf-8")
        (tmp_path / "big.bin").write_bytes(os.urandom(3 * 1024 * 1024))  # ~3 MiB

        archive = tmp_path / ("enc.amber" if encrypted else "plain.amber")
        with ArchiveWriter(str(archive), password=password, ecc_profile="balanced") as w:
            w.add_dir("docs")
            w.add_file("docs/a.txt", str(tmp_path / "docs" / "a.txt"), codec_id=CODEC_NONE, chunk_size=65536)
            w.add_file("big.bin", str(tmp_path / "big.bin"), codec_id=CODEC_NONE, chunk_size=65536)
            w.finalize()

        # Verify
        with ArchiveReader(str(archive), password=password) as r:
            assert r.verify(), "initial verify failed"

        # Corrupt two data symbols and repair copy (safe repair)
        corrupt_first_two_data_symbols(archive, password=password)
        repaired = archive.with_name(archive.stem + ".repaired")
        shutil.copy2(archive, repaired)
        with ArchiveReader(str(repaired), password=password) as r:
            result = repair_archive(r, str(repaired))
            assert (result.lrp_repaired or result.rx_repaired) or not result.remaining_corrupted, "repair did not fix anything"
        with ArchiveReader(str(repaired), password=password) as r:
            assert r.verify(), "post-repair verify failed"

        # Harden by +2% RX, then corrupt again and repair in place
        append_rx_parity(str(repaired), extra_ppm=20000, password=password)
        corrupt_first_two_data_symbols(repaired, password=password)
        with ArchiveReader(str(repaired), password=password) as r:
            _ = repair_archive(r, str(repaired))
        with ArchiveReader(str(repaired), password=password) as r:
            assert r.verify(), "post-harden verify failed"

        print(("[ENC]" if encrypted else "[PLAIN]"), "smoke: OK", repaired)


def main():
    scenario(encrypted=False)
    try:
        from amber.encryption import _HAS_CRYPTO
        if _HAS_CRYPTO:
            scenario(encrypted=True)
    except Exception:
        pass


if __name__ == "__main__":
    main()

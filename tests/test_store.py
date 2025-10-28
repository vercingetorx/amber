from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
import random
import time

from typing import Optional

from amber.writer import ArchiveWriter
from amber.reader import ArchiveReader
from amber.ecc import repair_archive
from amber.harden import append_rx_parity
from amber.rebuild import rebuild_archive
from amber.recover import rebuild_index
from amber.cli import cmd_repair, cmd_unseal
from amber.constants import INDEX_FRAME_MAGIC
from amber.encryption import (
    _HAS_CRYPTO,
    ARGON_TIME_COST,
    ARGON_MEMORY_COST_KIB,
    ARGON_PARALLELISM,
)
from amber.records import _REC_HDR_STRUCT


def _create_sample_files(base: Path):
    (base / "docs").mkdir()
    (base / "docs" / "a.txt").write_text("hello world\n" * 50, encoding="utf-8")
    (base / "docs" / "b.bin").write_bytes(os.urandom(4096))
    (base / "notes.md").write_text("# Title\nSome content\n", encoding="utf-8")


def _build_archive(base: Path, *, password: Optional[str] = None) -> Path:
    archive_path = base / "sample.amber"
    with ArchiveWriter(str(archive_path), password=password) as writer:
        writer.add_dir("docs")
        writer.add_file("docs/a.txt", str(base / "docs" / "a.txt"))
        writer.add_file("docs/b.bin", str(base / "docs" / "b.bin"))
        writer.add_file("notes.md", str(base / "notes.md"))
        writer.finalize()
    return archive_path


def _corrupt_symbol(path: Path, symbol, offset: int = 0):
    with open(path, "rb+") as fh:
        fh.seek(symbol.offset + offset)
        original = fh.read(1)
        if not original:
            return
        fh.seek(symbol.offset + offset)
        fh.write(bytes([original[0] ^ 0xFF]))


def _entry_signature_map(reader: ArchiveReader):
    snapshot = {}
    for e in reader.list():
        snapshot[e.path] = {
            "kind": e.kind,
            "size": getattr(e, "size", 0),
            "mode": getattr(e, "mode", 0),
            "file_codec": getattr(e, "file_codec", None),
            "chunk_size": getattr(e, "chunk_size", None),
            "chunk_count": len(getattr(e, "chunks", []) or []),
            "symlink_target": getattr(e, "symlink_target", None),
        }
    return snapshot


def _split_stat_time(st, base: str):
    ns_attr = f"{base}_ns"
    ns_val = getattr(st, ns_attr, None)
    if ns_val is not None:
        sec = int(ns_val // 1_000_000_000)
        nsec = int(ns_val % 1_000_000_000)
        return sec, nsec
    val = getattr(st, base, None)
    if val is None:
        return None, None
    sec = int(val)
    frac = val - sec
    nsec = int(round(frac * 1_000_000_000))
    if nsec >= 1_000_000_000:
        sec += 1
        nsec -= 1_000_000_000
    return sec, nsec


class AmberTests(unittest.TestCase):
    def run_with_tmpdir(self, func):
        with tempfile.TemporaryDirectory() as tmp:
            func(Path(tmp))

    def test_roundtrip_and_verify(self):
        def scenario(tmp_path: Path):
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            with ArchiveReader(str(archive_path)) as reader:
                paths = {e.path for e in reader.list()}
                self.assertIn("docs", paths)
                self.assertIn("docs/a.txt", paths)
                self.assertIn("docs/b.bin", paths)
                self.assertIn("notes.md", paths)
                self.assertTrue(reader.verify())
                self.assertTrue(reader.anchors_meta)
                self.assertTrue(reader.anchors_data)

        self.run_with_tmpdir(scenario)

    def test_rebuild_roundtrip(self):
        def scenario(tmp_path: Path):
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            with ArchiveReader(str(archive_path)) as reader:
                before = _entry_signature_map(reader)
                self.assertTrue(reader.verify())
            backup_path = rebuild_archive(str(archive_path))
            expected_backup = archive_path.with_name(archive_path.name + ".bak")
            self.assertEqual(expected_backup, backup_path)
            self.assertTrue(backup_path.exists())
            with ArchiveReader(str(archive_path)) as reader:
                after = _entry_signature_map(reader)
                self.assertTrue(reader.verify())
            self.assertEqual(before, after)
            with ArchiveReader(str(backup_path)) as reader_backup:
                self.assertTrue(reader_backup.verify())

        self.run_with_tmpdir(scenario)

    def test_directory_metadata_preserved_on_extract(self):
        def scenario(tmp_path: Path):
            src_dir = tmp_path / "src"
            src_dir.mkdir()
            tracked = src_dir / "tracked"
            tracked.mkdir()
            os.chmod(tracked, 0o705)
            base_mtime = int(time.time()) - 5000
            base_atime = base_mtime - 120
            os.utime(tracked, (base_atime, base_mtime))
            st = os.stat(tracked)
            m_sec, m_nsec = _split_stat_time(st, "st_mtime")
            a_sec, a_nsec = _split_stat_time(st, "st_atime")
            archive_path = tmp_path / "dir_meta.amber"
            with ArchiveWriter(str(archive_path)) as writer:
                writer.add_dir(
                    "tracked",
                    mode=st.st_mode & 0o7777,
                    mtime_sec=m_sec,
                    mtime_nsec=m_nsec,
                    atime_sec=a_sec,
                    atime_nsec=a_nsec,
                )
                writer.finalize()

            if m_sec is not None:
                with ArchiveReader(str(archive_path)) as reader:
                    dir_entry = next(e for e in reader.list() if e.path == "tracked")
                    self.assertEqual(dir_entry.mtime_sec, m_sec)

            outdir = tmp_path / "out"
            outdir.mkdir()
            cmd_unseal(
                str(archive_path),
                outdir=str(outdir),
                password=None,
                paths=None,
                exists="rename",
            )

            extracted = outdir / "tracked"
            self.assertTrue(extracted.is_dir())
            est = os.stat(extracted)
            self.assertEqual(est.st_mode & 0o7777, st.st_mode & 0o7777)
            if m_sec is not None:
                self.assertEqual(int(est.st_mtime), int(m_sec))

        self.run_with_tmpdir(scenario)

    def test_repair_single_symbol(self):
        def scenario(tmp_path: Path):
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            with ArchiveReader(str(archive_path)) as reader:
                target = next(info for info in reader.symbols if not info.is_parity)
                _corrupt_symbol(archive_path, target, offset=10)
            with ArchiveReader(str(archive_path)) as reader:
                result = repair_archive(reader, str(archive_path))
                self.assertTrue(result.lrp_repaired or result.rx_repaired)
            with ArchiveReader(str(archive_path)) as reader:
                self.assertTrue(reader.verify())

        self.run_with_tmpdir(scenario)

    def test_append_parity_and_repair(self):
        def scenario(tmp_path: Path):
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            added = append_rx_parity(str(archive_path), extra_ppm=800000)
            self.assertGreaterEqual(added, 1)
            with ArchiveReader(str(archive_path)) as reader:
                initial_total = len(reader.rx_parities)
                stripe_map = {}
                for info in reader.symbols:
                    if info.is_parity or info.stripe_index < 0:
                        continue
                    stripe_map.setdefault(info.stripe_index, []).append(info)
                target_stripe = next(vals for vals in stripe_map.values() if len(vals) >= 2)
                corrupt_targets = target_stripe[:2]
                offsets = [5, 20]
                for sym, off in zip(corrupt_targets, offsets):
                    _corrupt_symbol(archive_path, sym, offset=off)
                self.assertEqual(len(reader.rx_parities), initial_total)
                result = repair_archive(reader, str(archive_path))
                self.assertTrue(result.rx_repaired)
                self.assertFalse(result.remaining_corrupted)
            with ArchiveReader(str(archive_path)) as reader:
                self.assertTrue(reader.verify())

        self.run_with_tmpdir(scenario)

    @unittest.skipUnless(_HAS_CRYPTO, "PyCryptodomex required")
    def test_encrypted_roundtrip(self):
        def scenario(tmp_path: Path):
            password = "secret"
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path, password=password)
            with ArchiveReader(str(archive_path), password=password) as reader:
                paths = {e.path for e in reader.list()}
                self.assertIn("docs/a.txt", paths)
                self.assertTrue(reader.verify())
                parity_symbols = [info for info in reader.symbols if info.is_parity]
                self.assertTrue(parity_symbols)
                overhead = reader.decryptor.overhead() if reader.decryptor else 0
                for info in parity_symbols:
                    self.assertEqual(info.length, reader.symbol_size + overhead)

        self.run_with_tmpdir(scenario)

    @unittest.skipUnless(_HAS_CRYPTO, "PyCryptodomex required")
    def test_rebuild_roundtrip_encrypted(self):
        def scenario(tmp_path: Path):
            password = "secret"
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path, password=password)
            with ArchiveReader(str(archive_path), password=password) as reader:
                before = _entry_signature_map(reader)
                self.assertTrue(reader.verify())
            backup_path = rebuild_archive(str(archive_path), password=password)
            self.assertTrue(backup_path.exists())
            with ArchiveReader(str(archive_path), password=password) as reader:
                after = _entry_signature_map(reader)
                self.assertTrue(reader.verify())
            self.assertEqual(before, after)
            with ArchiveReader(str(backup_path), password=password) as reader_backup:
                self.assertTrue(reader_backup.verify())

        self.run_with_tmpdir(scenario)

    @unittest.skipUnless(_HAS_CRYPTO, "PyCryptodomex required")
    def test_encrypted_superblock_records_argon_params(self):
        def scenario(tmp_path: Path):
            password = "secret"
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path, password=password)
            with ArchiveReader(str(archive_path), password=password) as reader:
                sb = reader.superblock
                self.assertIsNotNone(sb)
                self.assertEqual(sb.kdf_id, 1)
                self.assertEqual(len(sb.kdf_salt), 16)
                self.assertEqual(sb.argon_time_cost, ARGON_TIME_COST)
                self.assertEqual(sb.argon_memory_cost, ARGON_MEMORY_COST_KIB)
                self.assertEqual(sb.argon_parallelism, ARGON_PARALLELISM)
                self.assertIsNotNone(reader.decryptor)
                params = reader.decryptor.export_params()
                self.assertEqual(params.time_cost, ARGON_TIME_COST)
                self.assertEqual(params.memory_cost_kib, ARGON_MEMORY_COST_KIB)
                self.assertEqual(params.parallelism, ARGON_PARALLELISM)

        self.run_with_tmpdir(scenario)

    @unittest.skipUnless(_HAS_CRYPTO, "PyCryptodomex required")
    def test_encrypted_repair_and_harden(self):
        def scenario(tmp_path: Path):
            password = "secret"
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path, password=password)
            with ArchiveReader(str(archive_path), password=password) as reader:
                stripe_map = {}
                for info in reader.symbols:
                    if info.is_parity or info.stripe_index < 0:
                        continue
                    stripe_map.setdefault(info.stripe_index, []).append(info)
                target_stripe = next(vals for vals in stripe_map.values() if len(vals) >= 2)
                corrupt_targets = target_stripe[:2]
            with open(archive_path, "rb+") as fh:
                for sym, off in zip(corrupt_targets, [5, 20]):
                    fh.seek(sym.offset + off)
                    b = fh.read(1)
                    fh.seek(sym.offset + off)
                    fh.write(bytes([b[0] ^ 0xFF]))

            added = append_rx_parity(str(archive_path), extra_ppm=300000, password=password)
            self.assertGreaterEqual(added, 1)

            with ArchiveReader(str(archive_path), password=password) as reader:
                result = repair_archive(reader, str(archive_path))
                self.assertTrue(result.rx_repaired or result.lrp_repaired)
            with ArchiveReader(str(archive_path), password=password) as reader:
                self.assertTrue(reader.verify())

        self.run_with_tmpdir(scenario)

    def test_rx_mixed_groups_small_append_repair(self):
        def scenario(tmp_path: Path):
            # Build a base archive with n >= 32 using 64 KiB chunks (uncompressed)
            base_file = tmp_path / "big.bin"
            base_file.write_bytes(os.urandom(3 * 1024 * 1024))  # ~3 MiB
            archive_path = tmp_path / "mixed.amber"
            from amber.constants import CODEC_NONE
            with ArchiveWriter(str(archive_path), ecc_profile="balanced") as w:
                w.add_file("big.bin", str(base_file), codec_id=CODEC_NONE, chunk_size=65536)
                w.finalize()

            # Append a tiny file to create a new small RX group (n < 32)
            small_file = tmp_path / "tiny.bin"
            small_file.write_bytes(os.urandom(128 * 1024))  # 128 KiB -> ~2 symbols
            from amber.append import append_to_archive
            append_to_archive(str(archive_path), [str(small_file)], ecc_profile="balanced")

            # Identify the last group's data symbols and corrupt two of them
            with ArchiveReader(str(archive_path)) as reader:
                groups = reader.index.get("ecc_groups", [])
                self.assertTrue(groups)
                gid = max(int(g.get("group_id", 0) or 0) for g in groups)
                last = next(g for g in groups if int(g.get("group_id", 0) or 0) == gid)
                data_indices = [int(s["symbol_index"]) for s in last.get("symbols", []) if not s.get("is_parity", False)]
                self.assertGreaterEqual(len(data_indices), 2)
                targets = data_indices[:2]
            with open(archive_path, "rb+") as fh:
                for t in targets:
                    sym = None
                    with ArchiveReader(str(archive_path)) as reader:
                        sym = reader.symbols[t]
                    fh.seek(sym.offset)
                    b = fh.read(1)
                    fh.seek(sym.offset)
                    fh.write(bytes([b[0] ^ 0xFF]))

            # Repair and verify
            with ArchiveReader(str(archive_path)) as reader:
                result = repair_archive(reader, str(archive_path))
                fixed = set(result.lrp_repaired + result.rx_repaired)
                # Ensure we repaired at least one of the targets and nothing remains
                self.assertTrue(fixed.intersection(set(targets)))
                self.assertFalse(result.remaining_corrupted)
            with ArchiveReader(str(archive_path)) as reader:
                self.assertTrue(reader.verify())

        self.run_with_tmpdir(scenario)

    def test_rebuild_index_detects_missing_chunks(self):
        def scenario(tmp_path: Path):
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            with ArchiveReader(str(archive_path)) as reader:
                file_entry = next(e for e in reader.list() if e.kind == 0 and e.path == "docs/a.txt")
                self.assertGreater(len(file_entry.chunks), 0)
                chunk_offset = file_entry.chunks[0].offset
            with open(archive_path, "rb+") as fh:
                fh.seek(chunk_offset)
                header = bytearray(fh.read(_REC_HDR_STRUCT.size))
                header[0] ^= 0xFF  # break record sync so chunk is skipped during rebuild
                fh.seek(chunk_offset)
                fh.write(header)
            with self.assertRaisesRegex(RuntimeError, "missing chunk"):
                rebuild_index(str(archive_path))

        self.run_with_tmpdir(scenario)

    def test_rx_tinyn_repair_n3_n5(self):
        def build_and_test(tmp_path: Path, n: int):
            archive_path = tmp_path / f"tiny_n{n}.amber"
            from amber.constants import CODEC_NONE
            with ArchiveWriter(str(archive_path), ecc_profile="balanced") as w:
                for i in range(n):
                    p = tmp_path / f"f{i}.bin"
                    p.write_bytes(os.urandom(65536))  # exactly one symbol each
                    w.add_file(f"f{i}.bin", str(p), codec_id=CODEC_NONE, chunk_size=65536)
                w.finalize()
            # Corrupt two data symbols
            with ArchiveReader(str(archive_path)) as reader:
                data_syms = [s for s in reader.symbols if not s.is_parity]
                self.assertGreaterEqual(len(data_syms), n)
                targets = [data_syms[0], data_syms[-1]] if len(data_syms) >= 2 else [data_syms[0]]
            with open(archive_path, "rb+") as fh:
                for sym in targets:
                    fh.seek(sym.offset)
                    b = fh.read(1)
                    fh.seek(sym.offset)
                    fh.write(bytes([b[0] ^ 0xFF]))
            with ArchiveReader(str(archive_path)) as reader:
                result = repair_archive(reader, str(archive_path))
                # Remaining corruption is acceptable if it's only parity symbols
                if result.remaining_corrupted:
                    remaining_data = []
                    for idx in result.remaining_corrupted:
                        if not reader.symbols[idx].is_parity:
                            remaining_data.append(idx)
                    self.assertFalse(remaining_data)
            with ArchiveReader(str(archive_path)) as reader:
                self.assertTrue(reader.verify())

        def scenario(tmp_path: Path):
            build_and_test(tmp_path, 3)
            build_and_test(tmp_path, 5)

        self.run_with_tmpdir(scenario)

    @unittest.skipUnless(_HAS_CRYPTO, "PyCryptodomex required")
    def test_encrypted_mixed_groups_small_append_repair(self):
        def scenario(tmp_path: Path):
            password = "secret"
            base_file = tmp_path / "big.bin"
            base_file.write_bytes(os.urandom(3 * 1024 * 1024))
            archive_path = tmp_path / "mixed_enc.amber"
            from amber.constants import CODEC_NONE
            with ArchiveWriter(str(archive_path), password=password, ecc_profile="balanced") as w:
                w.add_file("big.bin", str(base_file), codec_id=CODEC_NONE, chunk_size=65536)
                w.finalize()

            small_file = tmp_path / "tiny.bin"
            small_file.write_bytes(os.urandom(128 * 1024))
            from amber.append import append_to_archive
            append_to_archive(str(archive_path), [str(small_file)], password=password, ecc_profile="balanced")

            with ArchiveReader(str(archive_path), password=password) as reader:
                groups = reader.index.get("ecc_groups", [])
                gid = max(int(g.get("group_id", 0) or 0) for g in groups)
                last = next(g for g in groups if int(g.get("group_id", 0) or 0) == gid)
                data_indices = [int(s["symbol_index"]) for s in last.get("symbols", []) if not s.get("is_parity", False)]
                targets = data_indices[:2]
            with open(archive_path, "rb+") as fh:
                with ArchiveReader(str(archive_path), password=password) as reader:
                    for t in targets:
                        sym = reader.symbols[t]
                        fh.seek(sym.offset)
                        b = fh.read(1)
                        fh.seek(sym.offset)
                        fh.write(bytes([b[0] ^ 0xFF]))

            with ArchiveReader(str(archive_path), password=password) as reader:
                result = repair_archive(reader, str(archive_path))
                self.assertFalse(result.remaining_corrupted)
            with ArchiveReader(str(archive_path), password=password) as reader:
                self.assertTrue(reader.verify())

        self.run_with_tmpdir(scenario)

    def test_auto_rebuild_after_tail_truncate_plain(self):
        def scenario(tmp_path: Path):
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            # Corrupt one data symbol
            with ArchiveReader(str(archive_path)) as reader:
                target = next(info for info in reader.symbols if not info.is_parity)
                _corrupt_symbol(archive_path, target, offset=0)
                # Truncate index/trailer to force rebuild (anchors remain)
                trunc = reader.index_region_start
            with open(archive_path, "rb+") as fh:
                fh.truncate(trunc)
            # Repair should auto-rebuild index then fix corruption
            cmd_repair(str(archive_path), password=None, safe=False, output=None)
            with ArchiveReader(str(archive_path)) as reader:
                # Plaintext frames: magic at frame offset
                with open(archive_path, "rb") as fh:
                    fh.seek(reader.index_frame_offset)
                    magic = fh.read(8)
                    self.assertEqual(magic, INDEX_FRAME_MAGIC)
                self.assertTrue(reader.verify())

        self.run_with_tmpdir(scenario)

    @unittest.skipUnless(_HAS_CRYPTO, "PyCryptodomex required")
    def test_auto_rebuild_after_tail_truncate_encrypted(self):
        def scenario(tmp_path: Path):
            password = "secret"
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path, password=password)
            # Corrupt one data symbol
            with ArchiveReader(str(archive_path), password=password) as reader:
                target = next(info for info in reader.symbols if not info.is_parity)
                _corrupt_symbol(archive_path, target, offset=0)
                trunc = reader.index_region_start
            with open(archive_path, "rb+") as fh:
                fh.truncate(trunc)
            # Repair with password; auto-rebuild encrypted frames then fix
            cmd_repair(str(archive_path), password=password, safe=False, output=None)
            with ArchiveReader(str(archive_path), password=password) as reader:
                # Encrypted frames: bytes at frame offset should not equal magic
                with open(archive_path, "rb") as fh:
                    fh.seek(reader.index_frame_offset)
                    magic = fh.read(8)
                    self.assertNotEqual(magic, INDEX_FRAME_MAGIC)
                self.assertTrue(reader.verify())

        self.run_with_tmpdir(scenario)

    def test_safe_repair_copy(self):
        def scenario(tmp_path: Path):
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            with ArchiveReader(str(archive_path)) as reader:
                target = next(info for info in reader.symbols if not info.is_parity)
                _corrupt_symbol(archive_path, target, offset=0)
            cmd_repair(str(archive_path), password=None, safe=True, output=None)
            repaired = archive_path.with_name(archive_path.stem + ".repaired")
            self.assertTrue(repaired.exists())
            with ArchiveReader(str(repaired)) as reader:
                self.assertTrue(reader.verify())

        self.run_with_tmpdir(scenario)

    def test_extract_and_diff_plain(self):
        def scenario(tmp_path: Path):
            # Create archive
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            # Extract to out dir
            outdir = tmp_path / "out"
            outdir.mkdir()
            with ArchiveReader(str(archive_path)) as reader:
                for e in reader.list():
                    if e.kind == 0:
                        dst = outdir / e.path
                        reader.extract(e, str(dst))
            # Byte-compare files
            def read_bytes(p: Path) -> bytes:
                return p.read_bytes()
            # Expected files
            expected = {
                "docs/a.txt": read_bytes(tmp_path / "docs" / "a.txt"),
                "docs/b.bin": read_bytes(tmp_path / "docs" / "b.bin"),
                "notes.md": read_bytes(tmp_path / "notes.md"),
            }
            for rel, exp in expected.items():
                got = read_bytes(outdir / rel)
                self.assertEqual(got, exp)

        self.run_with_tmpdir(scenario)

    @unittest.skipUnless(_HAS_CRYPTO, "PyCryptodomex required")
    def test_extract_and_diff_encrypted(self):
        def scenario(tmp_path: Path):
            password = "secret"
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path, password=password)
            outdir = tmp_path / "out"
            outdir.mkdir()
            with ArchiveReader(str(archive_path), password=password) as reader:
                for e in reader.list():
                    if e.kind == 0:
                        dst = outdir / e.path
                        reader.extract(e, str(dst))
            def read_bytes(p: Path) -> bytes:
                return p.read_bytes()
            expected = {
                "docs/a.txt": read_bytes(tmp_path / "docs" / "a.txt"),
                "docs/b.bin": read_bytes(tmp_path / "docs" / "b.bin"),
                "notes.md": read_bytes(tmp_path / "notes.md"),
            }
            for rel, exp in expected.items():
                got = read_bytes(outdir / rel)
                self.assertEqual(got, exp)

        self.run_with_tmpdir(scenario)

    def test_parity_symbol_corruption_tolerated(self):
        def scenario(tmp_path: Path):
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            # Add substantial RX parity so we can tolerate some broken parity records
            append_rx_parity(str(archive_path), extra_ppm=300000)
            # Corrupt one data symbol and two RX parity symbols
            with ArchiveReader(str(archive_path)) as reader:
                data_syms = [s for s in reader.symbols if not s.is_parity]
                parity_syms = [s for s in reader.symbols if s.is_parity and s.stripe_index < 0]
                target_data = data_syms[0]
                corrupt_parities = parity_syms[:2]
            # Flip bytes
            _corrupt_symbol(archive_path, target_data, offset=0)
            for ps in corrupt_parities:
                _corrupt_symbol(archive_path, ps, offset=0)
            # Repair should ignore corrupted parities and still fix data
            with ArchiveReader(str(archive_path)) as reader:
                result = repair_archive(reader, str(archive_path))
                # Remaining corruption is acceptable if it's only parity symbols
                if result.remaining_corrupted:
                    remaining_data = []
                    for idx in result.remaining_corrupted:
                        if not reader.symbols[idx].is_parity:
                            remaining_data.append(idx)
                    self.assertFalse(remaining_data)
            with ArchiveReader(str(archive_path)) as reader:
                self.assertTrue(reader.verify())

        self.run_with_tmpdir(scenario)

    def test_random_data_losses_under_budget(self):
        def scenario(tmp_path: Path):
            # Build base archive and add lots of RX parity
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            # Add +50% RX to create plenty of equations
            append_rx_parity(str(archive_path), extra_ppm=500000)
            with ArchiveReader(str(archive_path)) as reader:
                data_syms = [s for s in reader.symbols if not s.is_parity]
            n = len(data_syms)
            # Corrupt up to ~10% of data symbols (at least 1)
            k = max(1, n // 10)
            victims = random.sample(data_syms, k)
            for s in victims:
                _corrupt_symbol(archive_path, s, offset=0)
            # Repair and verify
            with ArchiveReader(str(archive_path)) as reader:
                result = repair_archive(reader, str(archive_path))
                self.assertFalse(result.remaining_corrupted)
            with ArchiveReader(str(archive_path)) as reader:
                self.assertTrue(reader.verify())

        self.run_with_tmpdir(scenario)

    def test_repair_after_tail_truncate_and_no_anchors(self):
        def scenario(tmp_path: Path):
            # Build archive and then remove anchors + trailer, leaving only chunks
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            # Find earliest anchor offset and truncate before it
            with ArchiveReader(str(archive_path)) as reader:
                # Sanity: anchors exist
                self.assertTrue(reader.anchors_meta)
                # Truncate to just before first anchor, nuking anchors+trailer
                first_anchor_off = min(m.get("offset", reader.index_region_start) for m in reader.anchors_meta)
                trunc = first_anchor_off
            with open(archive_path, "rb+") as fh:
                fh.truncate(trunc)
            # No corruption; repair should rebuild index and verify succeeds
            cmd_repair(str(archive_path), password=None, safe=False, output=None)
            with ArchiveReader(str(archive_path)) as reader:
                # RX may be absent when anchors missing
                self.assertTrue(reader.verify())
        self.run_with_tmpdir(scenario)

    def test_missing_anchors_disables_rx_multi_loss(self):
        def scenario(tmp_path: Path):
            _create_sample_files(tmp_path)
            archive_path = _build_archive(tmp_path)
            # Remove anchors and trailer
            with ArchiveReader(str(archive_path)) as reader:
                first_anchor_off = min(m.get("offset", reader.index_region_start) for m in reader.anchors_meta)
                # Capture an LRP stripe, corrupt two symbols from same stripe to require RX
                stripe_map = {}
                for info in reader.symbols:
                    if info.is_parity or info.stripe_index < 0:
                        continue
                    stripe_map.setdefault(info.stripe_index, []).append(info)
                stripe = next(vals for vals in stripe_map.values() if len(vals) >= 2)
                victims = stripe[:2]
            # Truncate file to before anchors
            with open(archive_path, "rb+") as fh:
                fh.truncate(first_anchor_off)
            # Corrupt two symbols (LRP alone can’t fix)
            for s in victims:
                _corrupt_symbol(archive_path, s, offset=0)
            # Repair should rebuild index but cannot RX; check RX is absent
            cmd_repair(str(archive_path), password=None, safe=False, output=None)
            with ArchiveReader(str(archive_path)) as reader:
                self.assertFalse(reader.rx_parities)  # RX disabled when anchors missing
        self.run_with_tmpdir(scenario)


if __name__ == "__main__":
    unittest.main()

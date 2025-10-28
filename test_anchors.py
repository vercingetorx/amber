from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from amber.writer import ArchiveWriter
from amber.reader import ArchiveReader
from amber.recover import rebuild_index
from amber.append import append_to_archive
from amber.records import _REC_HDR_STRUCT


def _make_big_file(p: Path, size_bytes: int) -> None:
    # Use incompressible data so we accumulate storage bytes quickly
    p.write_bytes(os.urandom(size_bytes))


class AnchorStructureTests(unittest.TestCase):
    def run_with_tmpdir(self, func):
        with tempfile.TemporaryDirectory() as tmp:
            func(Path(tmp))

    def test_rebuild_preserves_good_anchors(self):
        def scenario(tmp_path: Path):
            p = tmp_path / "a.amber"
            with ArchiveWriter(str(p), anchor_interval_bytes=4096) as w:
                big = tmp_path / "big.bin"
                _make_big_file(big, 3 * 1024 * 1024)
                w.add_file("f.bin", str(big))
                w.finalize()

            with ArchiveReader(str(p)) as r:
                orig = [int(am.get("offset", -1)) for am in (r.anchors_meta or [])]
                self.assertGreaterEqual(len(orig), 2)

            rebuild_index(str(p))

            with ArchiveReader(str(p)) as r2:
                rebuilt = [int(am.get("offset", -1)) for am in (r2.index.get("anchors") or [])]
                self.assertEqual(set(rebuilt), set(orig))

        self.run_with_tmpdir(scenario)

    def test_rebuild_drops_bad_anchor_keeps_good(self):
        def scenario(tmp_path: Path):
            p = tmp_path / "b.amber"
            with ArchiveWriter(str(p), anchor_interval_bytes=4096) as w:
                d = tmp_path / "d.bin"
                _make_big_file(d, 2 * 1024 * 1024)
                w.add_file("f.bin", str(d))
                w.finalize()

            with ArchiveReader(str(p)) as r:
                offs = [int(am.get("offset", -1)) for am in (r.anchors_meta or [])]
                self.assertGreaterEqual(len(offs), 2)

            # Corrupt the first anchor's payload (unencrypted case)
            with open(p, "r+b") as fh:
                first = offs[0]
                fh.seek(first)
                fixed = fh.read(_REC_HDR_STRUCT.size)
                # Parse header to locate payload
                sync, rtype, rflags, header_len, payload_len, hdr_crc, _ = _REC_HDR_STRUCT.unpack(fixed)
                fh.seek(first + _REC_HDR_STRUCT.size + header_len + 8)
                b = fh.read(1)
                fh.seek(fh.tell() - 1)
                fh.write(bytes([b[0] ^ 0xFF]))

            rebuild_index(str(p))

            with ArchiveReader(str(p)) as r2:
                rebuilt = [int(am.get("offset", -1)) for am in (r2.index.get("anchors") or [])]
                self.assertNotIn(offs[0], rebuilt)
                self.assertEqual(set(rebuilt), set(offs[1:]))

        self.run_with_tmpdir(scenario)

    def test_append_references_tail_anchor_only(self):
        def scenario(tmp_path: Path):
            p = tmp_path / "c.amber"
            with ArchiveWriter(str(p), anchor_interval_bytes=4096) as w:
                x = tmp_path / "x.bin"
                _make_big_file(x, 2 * 1024 * 1024)
                w.add_file("f.bin", str(x))
                w.finalize()

            with ArchiveReader(str(p)) as r:
                original_count = len(r.anchors_meta or [])
                self.assertGreaterEqual(original_count, 2)

            s = tmp_path / "s.txt"
            s.write_text("hello")
            append_to_archive(str(p), [str(s)])

            with ArchiveReader(str(p)) as r2:
                anchors = r2.index.get("anchors") or []
                # New policy: preserve prior anchors and add one new tail anchor
                self.assertEqual(len(anchors), original_count + 1)

        self.run_with_tmpdir(scenario)

if __name__ == "__main__":
    unittest.main()

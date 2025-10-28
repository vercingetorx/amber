from __future__ import annotations

import os
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Dict, Tuple

from amber.reader import ArchiveReader


def _random_bytes(size: int) -> bytes:
    return os.urandom(size)


def _build_fixture_tree(root: Path, *, include_symlink: bool = True) -> Dict[str, Tuple[str, bytes]]:
    files: Dict[str, Tuple[str, bytes]] = {}
    (root / "docs").mkdir()
    (root / "docs" / "notes").mkdir()
    content = b"hello world\n" * 20
    (root / "docs" / "readme.txt").write_bytes(content)
    os.chmod(root / "docs" / "readme.txt", 0o644)
    files["docs/readme.txt"] = ("file", content)

    bin_data = _random_bytes(2048)
    (root / "docs" / "notes" / "binary.bin").write_bytes(bin_data)
    os.chmod(root / "docs" / "notes" / "binary.bin", 0o600)
    files["docs/notes/binary.bin"] = ("file", bin_data)

    (root / "docs" / "notes" / "empty.txt").write_text("")
    files["docs/notes/empty.txt"] = ("file", b"")

    # Directory metadata reference
    os.chmod(root / "docs" / "notes", 0o750)
    when = int(time.time()) - 86400
    os.utime(root / "docs" / "notes", (when - 60, when))

    if include_symlink and hasattr(os, "symlink"):
        target = "notes"
        link_path = root / "docs" / "ln_notes"
        try:
            os.symlink(target, link_path)
            files["docs/ln_notes"] = ("symlink", target.encode("utf-8"))
        except (OSError, NotImplementedError):
            pass

    return files


def _compare_trees(src: Path, dst: Path):
    for root_src, dirs_src, files_src in os.walk(src):
        rel = os.path.relpath(root_src, src)
        root_dst = os.path.join(dst, rel) if rel != "." else dst
        assert os.path.isdir(root_dst), f"Missing directory: {root_dst}"

        dirs_src.sort()
        files_src.sort()
        dirs_dst = sorted(
            d for d in os.listdir(root_dst) if os.path.isdir(os.path.join(root_dst, d)) and not os.path.islink(os.path.join(root_dst, d))
        )
        files_dst = sorted(
            f for f in os.listdir(root_dst) if os.path.isfile(os.path.join(root_dst, f)) or os.path.islink(os.path.join(root_dst, f))
        )

        # Directories should match (excluding symlinks which appear in files_dst)
        expected_dirs = sorted([d for d in dirs_src if not os.path.islink(os.path.join(root_src, d))])
        assert dirs_dst == expected_dirs, f"Directory mismatch under {root_src}: {dirs_dst} != {expected_dirs}"

        for fname in files_src:
            src_path = Path(root_src) / fname
            dst_path = Path(root_dst) / fname
            if os.path.islink(src_path):
                if not os.path.islink(dst_path):
                    raise AssertionError(f"Expected symlink at {dst_path}")
                assert os.readlink(dst_path) == os.readlink(src_path)
            else:
                with open(src_path, "rb") as sf, open(dst_path, "rb") as df:
                    sdata = sf.read()
                    ddata = df.read()
                    assert sdata == ddata, f"File contents differ: {dst_path}"


class CLIIntegrationTests(unittest.TestCase):
    def run_cli(self, args, *, expect: int | None = 0, cwd: Path | None = None):
        cmd = [sys.executable, "-m", "amber.cli"] + list(args)
        env = os.environ.copy()
        repo_root = Path(__file__).resolve().parents[2]
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(repo_root) if not existing else f"{repo_root}{os.pathsep}{existing}"
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        if expect is not None and proc.returncode != expect:
            raise AssertionError(
                f"CLI exited {proc.returncode}, expected {expect}\nCommand: {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
            )
        return proc

    def make_temp_tree(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        data = _build_fixture_tree(root)
        return tmp, root, data

    def test_plain_roundtrip_and_rebuild(self):
        tmp_src = tempfile.TemporaryDirectory()
        tmp_workspace = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_src.cleanup)
        self.addCleanup(tmp_workspace.cleanup)

        src_root = Path(tmp_src.name)
        workspace = Path(tmp_workspace.name)
        _build_fixture_tree(src_root)

        archive = workspace / "archive.amber"
        self.run_cli(["seal", str(archive), str(src_root)])

        verify_proc = self.run_cli(["verify", str(archive)])
        self.assertIn("OK", verify_proc.stdout)

        extract_dir = workspace / "extract"
        extract_dir.mkdir()
        self.run_cli(["unseal", str(archive), "--outdir", str(extract_dir)])
        extraction_root = extract_dir / src_root.name if (extract_dir / src_root.name).exists() else extract_dir
        _compare_trees(src_root, extraction_root)

        bak_path = Path(str(archive) + ".bak")
        self.assertFalse(bak_path.exists())
        rebuild_proc = self.run_cli(["rebuild", str(archive)])
        self.assertTrue(bak_path.exists())
        self.assertIn("Backup", rebuild_proc.stdout)
        # Rebuild should maintain readability and integrity
        verify_rebuilt = self.run_cli(["verify", str(archive)])
        self.assertIn("OK", verify_rebuilt.stdout)
        # Content after rebuild should match original tree
        extract_after = workspace / "extract_after"
        extract_after.mkdir()
        self.run_cli(["unseal", str(archive), "--outdir", str(extract_after)])
        extraction_after_root = extract_after / src_root.name if (extract_after / src_root.name).exists() else extract_after
        _compare_trees(src_root, extraction_after_root)

    def test_conflict_policies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file_path = root / "file.txt"
            file_path.write_text("alpha")
            symlink_path = root / "link.txt"
            symlink_available = hasattr(os, "symlink")
            if symlink_available:
                try:
                    os.symlink("file.txt", symlink_path)
                except OSError:
                    symlink_available = False

            archive = root / "arc.amber"
            create_args = ["seal", str(archive), str(file_path)]
            if symlink_available:
                create_args.append(str(symlink_path))
            # Store file/symlink directly (no parent directory wrapper)
            self.run_cli(create_args)

            out_skip = root / "ex_skip"
            out_skip.mkdir()
            (out_skip / "file.txt").write_text("beta")
            skip_proc = self.run_cli(["unseal", str(archive), "--outdir", str(out_skip), "--exists", "skip"])
            self.assertIn("skipping: file.txt", skip_proc.stdout)
            self.assertEqual((out_skip / "file.txt").read_text(), "beta")

            out_rename = root / "ex_rename"
            out_rename.mkdir()
            (out_rename / "file.txt").write_text("beta")
            rename_proc = self.run_cli(["unseal", str(archive), "--outdir", str(out_rename), "--exists", "rename"])
            self.assertIn("renamed to", rename_proc.stdout)
            self.assertTrue((out_rename / "file.txt").exists())
            renamed_variants = [p for p in out_rename.iterdir() if p.name.startswith("file (")]
            self.assertTrue(renamed_variants, "Expected renamed copy")

            out_overwrite = root / "ex_overwrite"
            out_overwrite.mkdir()
            (out_overwrite / "file.txt").write_text("beta")
            self.run_cli(["unseal", str(archive), "--outdir", str(out_overwrite), "--exists", "overwrite"])
            self.assertEqual((out_overwrite / "file.txt").read_text(), "alpha")

    def test_append_harden_and_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_dir = root / "base"
            base_dir.mkdir()
            (base_dir / "base.bin").write_bytes(_random_bytes(4096))
            archive = root / "data.amber"
            self.run_cli(["seal", str(archive), str(base_dir)])

            appended_file = root / "new.txt"
            appended_file.write_text("new payload")
            self.run_cli(["append", str(archive), str(appended_file)])

            haunt_proc = self.run_cli(["verify", str(archive)])
            self.assertIn("OK", haunt_proc.stdout)

            self.run_cli(["harden", str(archive), "--extra-ppm", "10000"])

            # Ensure appended content can be extracted
            extracted = root / "after_append"
            extracted.mkdir()
            self.run_cli(["unseal", str(archive), "--outdir", str(extracted)])
            candidates = list(extracted.rglob(appended_file.name))
            self.assertTrue(candidates, "Appended file not extracted")
            self.assertEqual(candidates[0].read_text(), "new payload")

            # Corrupt a data symbol
            with ArchiveReader(str(archive)) as reader:
                target = next(sym for sym in reader.symbols if not sym.is_parity)
                with open(archive, "rb+") as fh:
                    fh.seek(target.offset)
                    b = fh.read(1)
                    fh.seek(target.offset)
                    fh.write(bytes([b[0] ^ 0x55]))

            verify_fail = self.run_cli(["verify", str(archive)], expect=None)
            self.assertNotEqual(verify_fail.returncode, 0)
            self.assertTrue(
                "FAIL" in verify_fail.stdout or "Error" in verify_fail.stderr,
                f"Unexpected verify output: stdout={verify_fail.stdout!r}, stderr={verify_fail.stderr!r}",
            )

            repaired_copy = root / "data.repaired"
            repair_proc = self.run_cli(["repair", str(archive), "--safe", "--output", str(repaired_copy)])
            self.assertTrue(repaired_copy.exists())
            self.assertIn("Repaired copy", repair_proc.stdout)

            repaired_verify = self.run_cli(["verify", str(repaired_copy)])
            self.assertIn("OK", repaired_verify.stdout)

    def test_encrypted_rebuild_roundtrip(self):
        from amber.encryption import _HAS_CRYPTO

        if not _HAS_CRYPTO:
            self.skipTest("PyCryptodomex not available")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / "enc"
            fixture.mkdir()
            (fixture / "file.txt").write_text("secret data")
            archive = root / "enc.amber"
            password = "p@ssw0rd"
            self.run_cli(["seal", str(archive), str(fixture), "--password", password])
            extract_dir = root / "extract"
            extract_dir.mkdir()
            self.run_cli(["unseal", str(archive), "--password", password, "--outdir", str(extract_dir)])
            extracted_root = extract_dir / fixture.name if (extract_dir / fixture.name).exists() else extract_dir
            self.assertEqual((extracted_root / "file.txt").read_text(), "secret data")

            self.run_cli(["rebuild", str(archive), "--password", password])
            rebuilt_verify = self.run_cli(["verify", str(archive), "--password", password])
            self.assertIn("OK", rebuilt_verify.stdout)
            post_extract = root / "extract_after"
            post_extract.mkdir()
            self.run_cli(["unseal", str(archive), "--password", password, "--outdir", str(post_extract)])
            post_root = post_extract / fixture.name if (post_extract / fixture.name).exists() else post_extract
            _compare_trees(fixture, post_root)

    def test_harden_refuses_when_dirty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_dir = root / "base"
            base_dir.mkdir()
            (base_dir / "data.bin").write_bytes(_random_bytes(4096))
            archive = root / "data.amber"
            self.run_cli(["seal", str(archive), str(base_dir)])

            with ArchiveReader(str(archive)) as reader:
                target = next(sym for sym in reader.symbols if not sym.is_parity)
                with open(archive, "rb+") as fh:
                    fh.seek(target.offset)
                    b = fh.read(1)
                    fh.seek(target.offset)
                    fh.write(bytes([b[0] ^ 0xAA]))

            proc = self.run_cli(["harden", str(archive)], expect=None)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            combined = proc.stderr + proc.stdout
            self.assertIn("Verification failed before harden", combined)

    def test_scrub_success_and_recursion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outer_archive = root / "outer.amber"
            inner_dir = root / "nested"
            inner_dir.mkdir()
            inner_archive = inner_dir / "inner.amber"

            src_outer = root / "outer_src"
            src_outer.mkdir()
            (src_outer / "file.txt").write_text("alpha")
            self.run_cli(["seal", str(outer_archive), str(src_outer)])

            src_inner = inner_dir / "inner_src"
            src_inner.mkdir()
            (src_inner / "file.txt").write_text("beta")
            self.run_cli(["seal", str(inner_archive), str(src_inner)])

            proc = self.run_cli(["scrub", "."], cwd=root)
            self.assertIn("Summary: ok=1", proc.stdout)

            proc_recursive = self.run_cli(["scrub", ".", "--recursive"], cwd=root)
            self.assertIn("Summary: ok=2", proc_recursive.stdout)

            proc_json = self.run_cli(["scrub", ".", "--harden-extra", "20000", "--json"], cwd=root)
            payload = json.loads(proc_json.stdout)
            self.assertEqual(payload["ok"], 1)
            self.assertTrue(any(r.get("harden_added", 0) > 0 for r in payload["results"]))

    def test_scrub_detects_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "sample.amber"
            src = root / "data"
            src.mkdir()
            (src / "file.bin").write_bytes(_random_bytes(2048))
            self.run_cli(["seal", str(archive), str(src)])

            with ArchiveReader(str(archive)) as reader:
                target = next(sym for sym in reader.symbols if not sym.is_parity)
                with open(archive, "rb+") as fh:
                    fh.seek(target.offset)
                    b = fh.read(1)
                    fh.seek(target.offset)
                    fh.write(bytes([b[0] ^ 0x11]))

            proc = self.run_cli(["scrub", "."], cwd=root, expect=None)
            self.assertNotEqual(proc.returncode, 0)
            output = proc.stdout + proc.stderr
            self.assertIn("FAIL", output)
            self.assertIn("Summary:", proc.stdout)


if __name__ == "__main__":
    unittest.main()

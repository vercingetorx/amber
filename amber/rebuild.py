from __future__ import annotations

import errno
import math
import os
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .reader import ArchiveReader, Entry as ReaderEntry
from .writer import ArchiveWriter
from .errors import AmberError
from .constants import FLAG_ENCRYPTED


@dataclass(frozen=True)
class EntrySignature:
    path: str
    kind: int
    size: int
    mode: int
    symlink_target: Optional[str]


class RebuildError(RuntimeError):
    """Raised when the rebuild operation cannot complete safely."""


def _snapshot_entries(entries: Iterable[ReaderEntry]) -> List[EntrySignature]:
    snap: List[EntrySignature] = []
    for ent in entries:
        mode = ent.mode or 0
        size = ent.size if ent.kind == 0 else 0
        snap.append(
            EntrySignature(
                path=ent.path,
                kind=ent.kind,
                size=size,
                mode=mode,
                symlink_target=ent.symlink_target,
            )
        )
    snap.sort(key=lambda e: (e.kind, e.path))
    return snap


def _infer_lrp_parameters(reader: ArchiveReader) -> Tuple[bool, Optional[int]]:
    if not reader.stripes:
        return False, None
    counts = [len(s.data_symbols) for s in reader.stripes if s.data_symbols]
    if not counts:
        return True, None
    lrp_k = Counter(counts).most_common(1)[0][0]
    return True, lrp_k


def _infer_rx_epsilon(reader: ArchiveReader) -> int:
    data_symbols = [info for info in reader.symbols if not info.is_parity]
    total_data = len(data_symbols)
    if total_data == 0:
        return 0
    target = len(reader.rx_parities)
    if target == 0:
        return 0
    return math.ceil(target * 1_000_000 / total_data)


def rebuild_archive(path: str, *, password: Optional[str] = None, backup_suffix: str = ".bak") -> Path:
    """
    Rebuilds an archive by extracting its contents to a temporary "staging"
    area, creating a new archive from the staged content, and then atomically
    swapping the new archive with the old one.

    This is a safe and robust way to rewrite an archive, as it ensures that
    the original archive is not modified until the new one has been successfully
    created and verified.

    Returns:
        The path to the backup of the original archive.
    """
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(src))
    if not src.is_file():
        raise RebuildError(f"Archive is not a regular file: {src}")

    archive_dir = src.parent or Path(".")
    suffix = src.suffix or ".amber"
    backup_path = archive_dir / (src.name + backup_suffix)
    if backup_path.exists():
        raise RebuildError(f"Backup already exists: {backup_path}")

    # Temporary outputs
    fd, temp_archive = tempfile.mkstemp(prefix="amber-rebuild-", suffix=suffix, dir=str(archive_dir))
    os.close(fd)
    temp_archive_path = Path(temp_archive)

    with tempfile.TemporaryDirectory(prefix="amber-rebuild-stage-") as stage_root_str:
        stage_root = Path(stage_root_str)
        reader_snapshot: List[EntrySignature] = []
        sb = None
        is_encrypted = False
        lrp_enabled = False
        lrp_k: Optional[int] = None
        rx_epsilon_ppm = 0

        with ArchiveReader(str(src), password=password) as reader:
            sb = reader.superblock
            if sb is None:
                raise RebuildError("Missing superblock in source archive")
            is_encrypted = bool(sb.flags & FLAG_ENCRYPTED)
            entries = reader.list()
            reader_snapshot = _snapshot_entries(entries)
            # Stage directories upfront to ensure parents exist
            dirs = sorted({ent.path for ent in entries if ent.kind == 1}, key=lambda p: (p.count("/"), p))
            dir_meta = {}
            for ent in entries:
                if ent.kind != 1:
                    continue
                dir_meta[ent.path] = {
                    "mode": ent.mode,
                    "mtime_sec": ent.mtime_sec,
                    "mtime_nsec": ent.mtime_nsec,
                    "atime_sec": ent.atime_sec,
                    "atime_nsec": ent.atime_nsec,
                }
            files = [ent for ent in entries if ent.kind == 0]
            symlinks = [ent for ent in entries if ent.kind == 2]
            # Extract files to the staging tree
            for file_entry in files:
                target_path = stage_root / file_entry.path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                reader.extract(file_entry, str(target_path))
                mode = file_entry.mode
                if mode is not None:
                    try:
                        os.chmod(target_path, mode)
                    except OSError as exc:
                        raise RebuildError(f"Failed to set mode on {target_path}: {exc}") from exc
                mtime_sec = file_entry.mtime_sec
                atime_sec = file_entry.atime_sec
                if mtime_sec is not None:
                    if atime_sec is None:
                        atime_sec = mtime_sec
                    try:
                        os.utime(target_path, (float(atime_sec), float(mtime_sec)), follow_symlinks=False)
                    except OSError as exc:
                        raise RebuildError(f"Failed to set timestamps on {target_path}: {exc}") from exc
            # Collect ECC configuration hints
            lrp_enabled, lrp_k = _infer_lrp_parameters(reader)
            rx_epsilon_ppm = _infer_rx_epsilon(reader)

        # Build new archive from staged content
        try:
            with ArchiveWriter(
                str(temp_archive_path),
                default_chunk_size=sb.default_chunk_size,
                default_codec=sb.default_codec,
                password=(password if is_encrypted else None),
                ecc_profile="balanced",
                lrp_enabled=lrp_enabled,
                lrp_k=lrp_k,
                rx_epsilon_ppm=rx_epsilon_ppm,
            ) as writer:
                # Directories first
                for d in dirs:
                    meta = dir_meta.get(d, {})
                    writer.add_dir(
                        d,
                        mode=meta.get("mode"),
                        mtime_sec=meta.get("mtime_sec"),
                        mtime_nsec=meta.get("mtime_nsec"),
                        atime_sec=meta.get("atime_sec"),
                        atime_nsec=meta.get("atime_nsec"),
                    )
                # Symlinks
                for link_entry in symlinks:
                    writer.add_symlink(link_entry.path, link_entry.symlink_target or "")
                # Files from staging
                for file_entry in files:
                    staged = stage_root / file_entry.path
                    codec = file_entry.file_codec
                    chunk_size = file_entry.chunk_size
                    mode = file_entry.mode
                    writer.add_file(
                        file_entry.path,
                        str(staged),
                        codec_id=codec,
                        chunk_size=chunk_size,
                        mode=mode,
                    )
                writer.finalize()
        except (AmberError, OSError, ValueError, RuntimeError):
            if temp_archive_path.exists():
                temp_archive_path.unlink(missing_ok=True)  # type: ignore[attr-defined]
            raise

        # Verify the newly built archive before swapping it in
        try:
            with ArchiveReader(str(temp_archive_path), password=(password if is_encrypted else None)) as rebuilt_reader:
                if not rebuilt_reader.verify():
                    raise RebuildError("Verification failed on rebuilt archive")
                rebuilt_snapshot = _snapshot_entries(rebuilt_reader.list())
                if rebuilt_snapshot != reader_snapshot:
                    raise RebuildError("Rebuilt archive contents differ from source archive")
        except (AmberError, OSError, ValueError, RuntimeError):
            if temp_archive_path.exists():
                temp_archive_path.unlink(missing_ok=True)  # type: ignore[attr-defined]
            raise

    # Swap archives atomically
    try:
        os.replace(str(src), str(backup_path))
        os.replace(str(temp_archive_path), str(src))
    except OSError:
        # Attempt to roll back; best effort
        if not src.exists() and backup_path.exists():
            try:
                os.replace(str(backup_path), str(src))
            except OSError as exc:
                import sys as _sys
                print(f"Warning: failed to restore original archive from backup during swap recovery: {exc}", file=_sys.stderr)
        if temp_archive_path.exists():
            temp_archive_path.unlink(missing_ok=True)  # type: ignore[attr-defined]
        raise

    # Cleanup temp archive path handle if rename succeeded (it no longer exists)
    return backup_path

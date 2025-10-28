from __future__ import annotations

import os
import sys
import time
import errno
import argparse
import json as _json
import getpass as _getpass
import concurrent.futures as _fut
import zlib

from pathlib import Path
from typing import List, Iterable, Dict, Any, Optional

from amber.writer import ArchiveWriter
from amber.reader import ArchiveReader
from amber.ecc import repair_archive
from amber.harden import append_rx_parity
from amber.append import append_to_archive
from amber.recover import rebuild_index
from amber.rebuild import rebuild_archive
from amber.errors import (
    AmberError,
    IndexLocatorError,
    IndexFrameError,
    IndexSizeError,
    IndexLengthMismatch,
    IndexHashMismatch,
    MerkleMismatch,
    ChunkBoundsError,
    SymbolBoundsError,
    DuplicateSymbolIndexError,
    SymbolIndexGapError,
    SymbolSizeMismatchError,
)


def _safe_chmod(path: str, mode: Optional[int]) -> None:
    """Best‑effort chmod that never raises.

    Args:
        path: Destination filesystem path to update.
        mode: POSIX mode to apply (e.g., 0o755). If None, no change is made.
    """
    if mode is None:
        return
    try:
        os.chmod(path, mode)
    except OSError as exc:
        print(f"Warning: failed to set mode on {path}: {exc}", file=sys.stderr)


def _safe_utime(path: str, atime: Optional[float], mtime: Optional[float]) -> None:
    """Best‑effort utime that never raises.

    Args:
        path: Destination filesystem path to update.
        atime: Access time (seconds since epoch). If None, mtime is reused.
        mtime: Modification time (seconds since epoch). If None, no change is made.
    """
    if mtime is None:
        return
    if atime is None:
        atime = mtime
    try:
        os.utime(path, (atime, mtime), follow_symlinks=False)
    except OSError as exc:
        print(f"Warning: failed to set timestamps on {path}: {exc}", file=sys.stderr)


def _combine_time(sec: Optional[int], nsec: Optional[int]) -> Optional[float]:
    """Combine integer seconds and nanoseconds into a float timestamp.

    Args:
        sec: Seconds since epoch.
        nsec: Nanoseconds component.

    Returns:
        A float seconds value or None if sec is None.
    """
    if sec is None:
        return None
    return float(sec) + float(nsec or 0) / 1_000_000_000.0


# -------- Scrub (exposed callable) --------

def _iter_archives(paths: Iterable[str], recursive: bool) -> Iterable[str]:
    """Yield .amber file paths from a list of paths and/or directories.

    Args:
        paths: Paths to scan (files or directories).
        recursive: When True, traverse directories recursively.
    """
    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for root, _dirs, files in os.walk(p):
                    for fn in files:
                        if fn.lower().endswith(".amber"):
                            yield os.path.join(root, fn)
            else:
                try:
                    entries = os.listdir(p)
                except OSError:
                    continue
                for fn in entries:
                    if fn.lower().endswith(".amber"):
                        yield os.path.join(p, fn)
        else:
            if p.lower().endswith(".amber"):
                yield p


def _scrub_one(path: str, pw: str | None, do_repair: bool, safe: bool, harden_ppm: int) -> Dict[str, Any]:
    """Verify (and optionally repair/harden) a single archive."""

    res: Dict[str, Any] = {"path": path, "status": "unknown", "lrp_fixed": 0, "rx_fixed": 0, "harden_added": 0}
    target = path
    try:
        with ArchiveReader(path, password=pw) as r:
            ok = r.verify()
    except (
        IndexLocatorError,
        IndexFrameError,
        IndexSizeError,
        IndexLengthMismatch,
        IndexHashMismatch,
        MerkleMismatch,
        ChunkBoundsError,
        SymbolBoundsError,
        DuplicateSymbolIndexError,
        SymbolIndexGapError,
        SymbolSizeMismatchError,
    ):
        res["status"] = "hint:repair"
        res["message"] = (
            "Index appears inconsistent or corrupted. "
            "Run 'amber repair --safe' to rebuild the index and attempt recovery."
        )
        return res
    except (AmberError, OSError, ValueError, RuntimeError, zlib.error) as exc:
        res["status"] = "fail"
        res["message"] = str(exc)
        return res

    if ok:
        res["status"] = "ok"
        return res
    if not do_repair:
        res["status"] = "fail"
        return res

    if safe:
        base, ext = os.path.splitext(path)
        target = base + ".repaired"
        import shutil

        shutil.copy2(path, target)

    try:
        with ArchiveReader(target, password=pw) as r:
            rep = repair_archive(r, target)
    except (
        IndexLocatorError,
        IndexFrameError,
        IndexSizeError,
        IndexLengthMismatch,
        IndexHashMismatch,
        MerkleMismatch,
        ChunkBoundsError,
        SymbolBoundsError,
        DuplicateSymbolIndexError,
        SymbolIndexGapError,
        SymbolSizeMismatchError,
    ):
        _ = rebuild_index(target, password=pw)
        with ArchiveReader(target, password=pw) as r:
            rep = repair_archive(r, target)
    except (AmberError, OSError, ValueError, RuntimeError, zlib.error) as exc:
        res["status"] = "fail"
        res["message"] = str(exc)
        return res

    res["lrp_fixed"] = len(rep.lrp_repaired)
    res["rx_fixed"] = len(rep.rx_repaired)
    try:
        with ArchiveReader(target, password=pw) as r:
            ok2 = r.verify()
    except (AmberError, OSError, ValueError, RuntimeError, zlib.error) as exc:
        res["status"] = "fail"
        res["message"] = str(exc)
        return res
    if not ok2:
        res["status"] = "fail"
        return res
    if harden_ppm > 0:
        try:
            added = append_rx_parity(target, extra_ppm=harden_ppm, password=pw)
        except (AmberError, OSError, ValueError, RuntimeError, zlib.error) as exc:
            res["status"] = "fail"
            res["message"] = str(exc)
            return res
        res["harden_added"] = int(added)
    res["status"] = "repaired"
    return res


def cmd_scrub(
    paths: List[str],
    *,
    recursive: bool = False,
    jobs: int = 4,
    password: Optional[str] = None,
    repair: bool = False,
    safe: bool = False,
    harden_extra: int = 0,
    as_json: bool = False,
    quiet: bool = False
) -> bool:
    """Verify many archives; optional auto‑repair and harden.

    Args:
        paths: Archive paths and/or directories to scan.
        recursive: Recurse into directories when True.
        jobs: Maximum parallel workers.
        password: Password for encrypted archives.
        repair: Attempt repair on failures.
        safe: When repairing, keep source unchanged and write a repaired copy.
        (Repaired copies always use the fixed suffix ".repaired".)
        harden_extra: If >0 and the target verifies clean (repaired or original),
            append RX parity at the given density (ppm) to the archive’s latest ECC
            group. Runs regardless of the repair flag; in verify‑only mode, it writes
            in‑place unless --safe is provided (which writes to a copy with suffix ".repaired").
        as_json: When True, print a JSON result summary.

    Returns:
        True when no archives failed verification, False otherwise.

    Raises:
        RuntimeError: If no archives matching the input paths were found.
    """
    paths = list(_iter_archives(paths, recursive))
    if not paths:
        raise RuntimeError("No archives found")
    # Password management: reuse provided; prompt once lazily if needed
    pw_holder = {"pw": password}

    def _runner(p: str) -> Dict[str, Any]:
        pw = pw_holder["pw"]
        try:
            return _scrub_one(p, pw, repair, safe, harden_extra)
        except ValueError as e:
            if "password required" in str(e).lower() and pw is None:
                pw_holder["pw"] = _getpass.getpass("Archive password: ")
                return _scrub_one(p, pw_holder["pw"], repair, safe, harden_extra)
            raise

    results: List[Dict[str, Any]] = []
    with _fut.ThreadPoolExecutor(max_workers=max(1, int(jobs))) as ex:
        for r in ex.map(_runner, paths):
            results.append(r)
    ok = sum(1 for r in results if r.get("status") in ("ok", "repaired"))
    repaired_ct = sum(1 for r in results if r.get("status") == "repaired")
    failed = sum(1 for r in results if (r.get("status", "").startswith("error") or r.get("status") == "fail" or r.get("status", "").startswith("hint")))
    if as_json:
        print(_json.dumps({"results": results, "ok": ok, "repaired": repaired_ct, "failed": failed}))
    else:
        for r in results:
            status = r.get("status", "unknown")
            if not quiet:
                line = f"{status.upper():8s} {r['path']} (lrp={r['lrp_fixed']} rx={r['rx_fixed']} harden+={r['harden_added']})"
                print(line)
            # QUESTION: should this be gated by quiet?
            if status.startswith("hint") and r.get("message"):
                print("  " + r["message"])  # indent one level
        print(f"Summary: ok={ok} repaired={repaired_ct} failed={failed}")
    return failed == 0


def cmd_append(archive: str, inputs: list[str], *, password: Optional[str] = None, ecc_profile: str = "balanced") -> bool:
    """Append files to an existing archive and rewrite the trailer.

    Args:
        archive: Path to the .amber file to modify.
        inputs: List of file or directory paths to append.
        password: Password for encrypted archives.
        ecc_profile: ECC preset for the appended segment.
    """
    print(" Appending files and rewriting index...", flush=True)
    append_to_archive(archive, inputs, password=password, ecc_profile=ecc_profile)
    return True


def cmd_seal(output: str, inputs: list[str], *, password: Optional[str] = None, ecc_profile: str = "balanced", quiet: bool = False) -> bool:
    """Seal (create) a new archive from filesystem paths.

    Args:
        output: Path to the output .amber file to write.
        inputs: List of file or directory paths to store.
        password: Optional encryption password; when provided, all records are AEAD‑protected.
        ecc_profile: ECC preset: "lean", "balanced" (default), or "archival".
    """
    out = output
    inputs = [Path(x) for x in inputs]

    dirs: list[tuple[str, Dict[str, Optional[int]]]] = []
    files: list[tuple[str, str, int]] = []
    symlinks: list[tuple[str, str]] = []

    def _split_time_components(st: os.stat_result, ns_attr: str, attr: str) -> tuple[Optional[int], Optional[int]]:
        ns_val = getattr(st, ns_attr, None)
        if ns_val is not None:
            sec = int(ns_val // 1_000_000_000)
            nsec = int(ns_val % 1_000_000_000)
            return sec, nsec
        val = getattr(st, attr, None)
        if val is None:
            return None, None
        sec = int(val)
        frac = val - sec
        nsec = int(round(frac * 1_000_000_000))
        if nsec >= 1_000_000_000:
            sec += 1
            nsec -= 1_000_000_000
        return sec, nsec

    def _dir_metadata(fs_path: Path) -> Dict[str, Optional[int]]:
        meta: Dict[str, Optional[int]] = {
            "mode": None,
            "mtime_sec": None,
            "mtime_nsec": None,
            "atime_sec": None,
            "atime_nsec": None,
        }
        try:
            st = os.stat(str(fs_path))
        except OSError:
            return meta
        meta["mode"] = st.st_mode & 0o7777
        m_sec, m_nsec = _split_time_components(st, "st_mtime_ns", "st_mtime")
        a_sec, a_nsec = _split_time_components(st, "st_atime_ns", "st_atime")
        meta["mtime_sec"], meta["mtime_nsec"] = m_sec, m_nsec
        meta["atime_sec"], meta["atime_nsec"] = a_sec, a_nsec
        return meta

    for p in inputs:
        if p.is_symlink():
            symlinks.append((p.name, os.readlink(str(p))))
        elif p.is_dir():
            base = p.name
            dirs.append((base, _dir_metadata(p)))
            for root, dirnames, filenames in os.walk(str(p)):
                for d in dirnames:
                    sub = os.path.join(root, d)
                    if os.path.islink(sub):
                        continue
                    rel = os.path.relpath(sub, start=str(p))
                    arc = os.path.join(base, rel)
                    dirs.append((arc, _dir_metadata(Path(sub))))
                # prune symlink directories to avoid walking into them
                dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(root, d))]
                for f in filenames:
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, start=str(p))
                    arc = os.path.join(base, rel)
                    try:
                        size = os.path.getsize(full)
                    except OSError:
                        size = 0
                    files.append((arc, full, size))
        else:
            try:
                size = os.path.getsize(str(p))
            except OSError:
                size = 0
            files.append((p.name, str(p), size))

    total_bytes = sum(sz for _, _, sz in files) or 1
    processed = 0

    t0 = time.time()

    with ArchiveWriter(out, password=password, ecc_profile=ecc_profile) as w:
        # Add directories (deduped)
        seen = set()
        for arc, meta in dirs:
            if arc in seen:
                continue
            seen.add(arc)
            w.add_dir(
                arc,
                mode=meta.get("mode"),
                mtime_sec=meta.get("mtime_sec"),
                mtime_nsec=meta.get("mtime_nsec"),
                atime_sec=meta.get("atime_sec"),
                atime_nsec=meta.get("atime_nsec"),
            )

        for arc, target in symlinks:
            w.add_symlink(arc, target)

        for arc, full, size in files:
            w.add_file(arc, full)
            processed += size
            if not quiet:
                pct = processed * 100.0 / total_bytes
                print(f" {pct:6.2f}% sealing: {arc}")

        # Finalization can take a moment: RX parity, anchors, index
        print(" Finalizing (RX parity, anchors, index)...", flush=True)
        w.finalize()

    # Final summary line
    dt = max(0.000001, time.time() - t0)
    unique_dirs = len({arc for arc, _ in dirs})
    n_files = len(files)
    n_links = len(symlinks)
    mib = processed / (1024.0 * 1024.0)
    mbps = mib / dt
    profile = ecc_profile or "balanced"
    if profile == "lean":
        lrp_pct, rx_pct, total_pct = 0.0, 2.0, 2.0
    elif profile == "archival":
        lrp_pct, rx_pct, total_pct = (100.0/12.0), 4.0, (100.0/12.0)+4.0
    else:  # balanced
        lrp_pct, rx_pct, total_pct = (100.0/16.0), 2.0, (100.0/16.0)+2.0

    print(
        f"Done: {n_files} files, {unique_dirs} dirs, {n_links} links; "
        f"{mib:.2f} MiB in {dt:.1f}s; {mbps:.2f} MiB/s; "
        f"ECC={profile} (~{total_pct:.2f}%: LRP {lrp_pct:.2f}% + RX {rx_pct:.2f}%)"
    )
    return True


def cmd_list(archive: str, *, password: Optional[str] = None) -> bool:
    """List archive entries.

    Args:
        archive: Path to an .amber file.
        password: Password for encrypted archives.
    """
    # Read-only; on index/pointer errors, provide guidance instead of modifying
    try:
        with ArchiveReader(archive, password=password) as r:
            entries = r.list()
            if r.anchor_fail_count > 0:
                print(
                    f"Warning: {r.anchor_fail_count}/{r.anchor_total_count} anchor(s) could not be read. "
                    "Anchors are not critical; run 'amber rebuild' to fix anchor references.",
                    file=sys.stderr,
                )
    except (
        IndexLocatorError,
        IndexFrameError,
        IndexSizeError,
        IndexLengthMismatch,
        IndexHashMismatch,
        MerkleMismatch,
        ChunkBoundsError,
        SymbolBoundsError,
        DuplicateSymbolIndexError,
        SymbolIndexGapError,
        SymbolSizeMismatchError,
    ):
            print(
                "Index appears inconsistent or corrupted. This command is read-only.\n"
                "Hint: run 'amber repair --safe' to rebuild the index and attempt recovery.",
                file=sys.stderr,
            )
            sys.exit(2)
    for e in entries:
        k = {0: "file", 1: "dir", 2: "symlink"}.get(e.kind, str(e.kind))
        if e.kind == 0:
            print(f"{k}\t{e.size}\t{e.path}")
        elif e.kind == 2 and e.symlink_target:
            print(f"{k}\t-> {e.symlink_target}\t{e.path}")
        else:
            print(f"{k}\t{e.path}")
    return True


def cmd_unseal(archive: str, *, outdir: str = ".", password: Optional[str] = None, paths: Optional[list[str]] = None, exists: str = "rename", quiet: bool = False) -> bool:
    """Unseal (extract) files from an archive to a directory."""

    from amber.pathutil import norm_path

    try:
        with ArchiveReader(archive, password=password) as r:
            entries = r.list()
            if r.anchor_fail_count > 0:
                print(
                    f"Warning: {r.anchor_fail_count}/{r.anchor_total_count} anchor(s) could not be read. "
                    "Anchors are not critical; run 'amber rebuild' to fix anchor references.",
                    file=sys.stderr,
                )

            reqs = paths or []
            if reqs:
                wanted = [norm_path(p) for p in reqs]
                filtered: List = []
                for e in entries:
                    ep = e.path
                    if any(ep == rp or ep.startswith(rp + "/") for rp in wanted):
                        filtered.append(e)
                entries = filtered

            t0 = time.time()
            def _next_nonconflicting_path(path: str) -> str:
                if not os.path.exists(path) and not os.path.lexists(path):
                    return path
                base_dir = os.path.dirname(path)
                name = os.path.basename(path)
                root, ext = os.path.splitext(name)
                i = 1
                while True:
                    candidate = os.path.join(base_dir, f"{root} ({i}){ext}")
                    if not os.path.exists(candidate) and not os.path.lexists(candidate):
                        return candidate
                    i += 1

            symlink_fn = getattr(os, "symlink", None)
            symlink_warning_emitted = False
            unsupported_symlink_errnos = {errno.EPERM, errno.EOPNOTSUPP}
            if hasattr(errno, "ENOTSUP"):
                unsupported_symlink_errnos.add(errno.ENOTSUP)
            unsupported_win_errors = {1314}
            file_entries = [e for e in entries if e.kind == 0]
            total_files = len(file_entries)
            total_symlinks = sum(1 for e in entries if e.kind == 2)
            processed_files = 0
            processed_bytes = 0
            renamed_entries = 0
            skipped_entries = 0
            created_dirs = 0
            created_symlinks = 0

            for e in entries:
                dst = os.path.join(outdir or ".", e.path)
                if e.kind == 1:
                    os.makedirs(dst, exist_ok=True)
                    print(f"   creating: {e.path}/")
                    _safe_chmod(dst, e.mode)
                    _safe_utime(dst, _combine_time(e.atime_sec, e.atime_nsec), _combine_time(e.mtime_sec, e.mtime_nsec))
                    created_dirs += 1
                    continue

                if e.kind == 2 and e.symlink_target:
                    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
                    actual_dst = dst
                    rename_note = None
                    if os.path.lexists(actual_dst):
                        if exists == "overwrite":
                            if os.path.isdir(actual_dst) and not os.path.islink(actual_dst):
                                raise RuntimeError(f"Cannot overwrite directory with symlink: {actual_dst}")
                            try:
                                os.remove(actual_dst)
                            except FileNotFoundError:
                                pass
                        elif exists == "skip":
                            print(f"    skipping: {e.path} (exists)")
                            skipped_entries += 1
                            continue
                        elif exists == "rename":
                            actual_dst = _next_nonconflicting_path(actual_dst)
                            rename_note = actual_dst
                        else:
                            raise RuntimeError(f"Destination exists: {actual_dst}")
                    if symlink_fn is None:
                        if not symlink_warning_emitted:
                            print("symlinks not supported; skipping")
                            symlink_warning_emitted = True
                        skipped_entries += 1
                        continue
                    try:
                        symlink_fn(e.symlink_target, actual_dst)
                        print(f"  symlinking: {e.path} -> {e.symlink_target}")
                        created_symlinks += 1
                        if rename_note:
                            print(f"       note: renamed to {actual_dst}")
                            renamed_entries += 1
                    except (NotImplementedError, AttributeError):
                        if not symlink_warning_emitted:
                            print("symlinks not supported; skipping")
                            symlink_warning_emitted = True
                        skipped_entries += 1
                    except OSError as exc:
                        if exc.errno in unsupported_symlink_errnos or getattr(exc, "winerror", None) in unsupported_win_errors:
                            if not symlink_warning_emitted:
                                print("symlinks not supported; skipping")
                                symlink_warning_emitted = True
                            skipped_entries += 1
                        else:
                            raise
                    continue

                if e.kind != 0:
                    continue

                processed_files += 1
                processed_bytes += e.size or 0
                os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
                actual_dst = dst
                rename_note = None
                if os.path.exists(actual_dst) or os.path.islink(actual_dst):
                    if exists == "overwrite":
                        if os.path.isdir(actual_dst) and not os.path.islink(actual_dst):
                            raise RuntimeError(f"Cannot overwrite directory with file: {actual_dst}")
                    elif exists == "skip":
                        print(f"    skipping: {e.path} (exists)")
                        skipped_entries += 1
                        continue
                    elif exists == "rename":
                        actual_dst = _next_nonconflicting_path(actual_dst)
                        rename_note = actual_dst
                    else:
                        raise RuntimeError(f"Destination exists: {actual_dst}")
                if not quiet:
                    print(f" unsealing: {processed_files:>4}/{total_files:<4} {e.path}")
                r.extract(e, actual_dst)
                if rename_note:
                    print(f"       note: renamed to {actual_dst}")
                    renamed_entries += 1
                _safe_chmod(actual_dst, e.mode)
                mtime_val = _combine_time(e.mtime_sec, e.mtime_nsec)
                atime_val = _combine_time(e.atime_sec, e.atime_nsec)
                if mtime_val is not None and atime_val is None:
                    from os.path import getatime
                    atime_val = float(getatime(actual_dst))
                _safe_utime(actual_dst, atime_val, mtime_val)
        dt = max(0.000001, time.time() - t0)
        mib = processed_bytes / (1024.0 * 1024.0)
        mbps = mib / dt
        symlink_summary = (
            str(created_symlinks) if total_symlinks == 0 else f"{created_symlinks}/{total_symlinks}"
        )
        print(
            f"Done: extracted {processed_files}/{total_files} files ({mib:.2f} MiB) in {dt:.1f}s; "
            f"{mbps:.2f} MiB/s; dirs={created_dirs} symlinks={symlink_summary}; "
            f"skipped={skipped_entries} renamed={renamed_entries}"
        )
        return True
    except (
        IndexLocatorError,
        IndexFrameError,
        IndexSizeError,
        IndexLengthMismatch,
        IndexHashMismatch,
        MerkleMismatch,
        ChunkBoundsError,
        SymbolBoundsError,
        DuplicateSymbolIndexError,
        SymbolIndexGapError,
        SymbolSizeMismatchError,
    ) as exc:
        print(
            "Index appears inconsistent or corrupted. This command is read-only.\n"
            "Hint: run 'amber repair --safe' to rebuild the index and attempt recovery.",
            file=sys.stderr,
        )
        sys.exit(2)
    except (AmberError, OSError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)


def cmd_verify(archive: str, *, password: Optional[str] = None) -> bool:
    """Verify archive integrity.

    Args:
        archive: Path to the .amber file.
        password: Password for encrypted archives.

    Prints:
        "OK" on success, "FAIL" on mismatch or errors.
    """
    try:
        with ArchiveReader(archive, password=password) as r:
            if r.anchor_fail_count > 0:
                print(
                    f"Warning: {r.anchor_fail_count}/{r.anchor_total_count} anchor(s) could not be read. "
                    "Anchors are not critical; run 'amber rebuild' to fix anchor references.",
                    file=sys.stderr,
                )
            ok = r.verify()
            print("OK" if ok else "FAIL")
            return ok
    except (
        IndexLocatorError,
        IndexFrameError,
        IndexSizeError,
        IndexLengthMismatch,
        IndexHashMismatch,
        MerkleMismatch,
    ):
            print(
                "Verification failed due to index corruption. This command is read-only.\n"
                "Hint: run 'amber repair --safe' to rebuild the index and attempt recovery.",
                file=sys.stderr,
            )
            sys.exit(2)


def cmd_repair(archive: str, *, password: Optional[str] = None, safe: bool = False, output: Optional[str] = None) -> bool:
    """Attempt ECC repair (and rebuild index if needed).

    Args:
        archive: Path to the .amber file (source or target depending on --safe).
        password: Password for encrypted archives.
        safe: When True, write a repaired copy and leave source unchanged.
        output: Optional repaired copy path; implies safe if provided.
    """
    import shutil
    src = archive
    dst = None
    if output:
        safe = True
        dst = output
    if safe:
        # Default output path if none provided: fixed ".repaired" suffix
        if not dst:
            base = os.path.basename(src)
            root, ext = os.path.splitext(base)
            dst = os.path.join(os.path.dirname(src), f"{root}.repaired")
        shutil.copy2(src, dst)
        target = dst
    else:
        target = src
    # Try to open; if index failure, rebuild automatically then continue
    try:
        with ArchiveReader(target, password=password) as r:
            result = repair_archive(r, target)
    except (
        IndexLocatorError,
        IndexFrameError,
        IndexSizeError,
        IndexLengthMismatch,
        IndexHashMismatch,
        MerkleMismatch,
        ChunkBoundsError,
        SymbolBoundsError,
        DuplicateSymbolIndexError,
        SymbolIndexGapError,
        SymbolSizeMismatchError,
    ):
        count = rebuild_index(target, password=password)
        with ArchiveReader(target, password=password) as r:
            result = repair_archive(r, target)
        print(f"Rebuilt index ({count} RX parity symbol(s)) and attempted repair")
    except (AmberError, OSError, ValueError, RuntimeError):
        raise
    if safe:
        print(f"Repaired copy written to: {target}")
    total_fixed = len(result.lrp_repaired) + len(result.rx_repaired)
    if result.lrp_repaired:
        print(f"LRP repaired symbols: {result.lrp_repaired}")
    if result.rx_repaired:
        print(f"RX repaired symbols: {result.rx_repaired}")
    if result.remaining_corrupted:
        print(f"Unrepaired symbols: {result.remaining_corrupted}")
        # Provide a high-level reason to help the user
        try:
            with ArchiveReader(target, password=password) as rr:
                has_lrp = bool(rr.stripes)
                has_rx = bool(rr.rx_parities)
                if not has_lrp and not has_rx:
                    print("Reason: archive has no ECC metadata; nothing to repair.")
                elif has_lrp and not has_rx:
                    print("Reason: only LRP present; stripes with >1 missing symbol cannot be repaired.")
                elif has_rx:
                    print("Reason: insufficient RX equations to solve remaining symbols. Consider hardening (append more RX parity).")
        except (AmberError, OSError, ValueError, RuntimeError) as exc:
            print(f"Warning: unable to summarize ECC features for hint: {exc}", file=sys.stderr)
    if total_fixed == 0 and not result.remaining_corrupted:
        print("No corruption detected")
    try:
        rebuilt_rx = rebuild_index(target, password=password)
        if rebuilt_rx:
            print(f"Rebuilt index metadata ({rebuilt_rx} RX parity symbol(s))")
        else:
            print("Rebuilt index metadata")
    except (AmberError, OSError, ValueError, RuntimeError) as exc:
        print(f"Error: failed to rebuild index metadata: {exc}", file=sys.stderr)
        raise
    return True


def cmd_rebuild(archive: str, *, password: Optional[str] = None) -> bool:
    """Fully rewrite an archive via staging and atomic swap.

    Args:
        archive: Path to the .amber file to rebuild.
        password: Password for encrypted archives.

    Prints:
        The backup path written during the swap.
    """
    backup_path = rebuild_archive(archive, password=password)
    print(f"Rebuilt archive committed. Backup written to: {backup_path}")
    return True


def cmd_harden(archive: str, *, extra_ppm: int = 20000, password: Optional[str] = None, ecc_profile: Optional[str] = None) -> bool:
    """Verify an archive and append extra RX parity to its latest ECC group.

    Args:
        archive: Path to the .amber file.
        extra_ppm: RX parity density to append in ppm (e.g., 20000 = 2%). Applies to the
            archive’s latest ECC group across all of its data symbols; does not rewrite
            existing file data or earlier ECC groups.
        password: Password for encrypted archives.
        ecc_profile: Optional profile ("lean"/"balanced"/"archival") to select amount;
            overrides extra_ppm.
    """
    try:
        with ArchiveReader(archive, password=password) as r:
            if not r.verify():
                raise RuntimeError("Verification failed; run amber repair before hardening.")
    except (AmberError, OSError, ValueError, RuntimeError, zlib.error) as exc:
        raise RuntimeError(f"Verification failed before harden: {exc}")
    extra = extra_ppm
    if ecc_profile:
        if ecc_profile == "lean":
            extra = 20000
        elif ecc_profile == "balanced":
            extra = 20000
        elif ecc_profile == "archival":
            extra = 40000
    pct = extra / 10000.0
    print(f" Appending ~{pct:.2f}% RX parity and rewriting index...", flush=True)
    added = append_rx_parity(archive, extra_ppm=extra, password=password)
    print(f"Appended {added} RX parity symbol(s)")
    return True


def cmd_info(archive: str, *, password: Optional[str] = None) -> bool:
    """Show archive information.

    Args:
        archive: Path to an .amber file.
        password: Password for encrypted archives.
    """
    with ArchiveReader(archive, password=password) as r:
        print(f"Archive: {archive}")
        if r.superblock:
            print(f"  Version: {r.superblock.version_major}.{r.superblock.version_minor}")
            print(f"  UUID: {r.superblock.uuid.hex()}")
            print(f"  Created: {r.superblock.created_sec}")
            print(f"  Flags: {r.superblock.flags}")
        if r.index:
            print(f"  Default chunk size: {r.index.get('default_chunk_size', 'N/A')}")
            print(f"  Default codec: {r.index.get('default_codec', 'N/A')}")
        print(f"  Entries: {len(r.entries)}")
        print(f"    Files: {len([e for e in r.entries if e.kind == 0])}")
        print(f"    Directories: {len([e for e in r.entries if e.kind == 1])}")
        print(f"    Symlinks: {len([e for e in r.entries if e.kind == 2])}")
    return True


def main(argv: List[str] | None = None):
    ap = argparse.ArgumentParser(
        prog="amber",
        description="Amber .amber archive tool",
        epilog=(
            "When encrypted, all records (data, parity, anchors, index) are AEAD‑protected."
        ),
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # seal
    ap_create = sub.add_parser("seal", help="Seal archive")
    ap_create.add_argument("output", help="Output .amber path")
    ap_create.add_argument("inputs", nargs="+", help="Input files/directories")
    ap_create.add_argument("--password", help="Encryption password")
    ap_create.add_argument("--quiet", help="limit outputs to summaries only", action="store_true")
    ap_create.add_argument(
        "--ecc-profile",
        choices=["lean", "balanced", "archival"],
        default="balanced",
        help=(
            "ECC profile (lean: ~2% RX; balanced: ~8.25% = LRP 6.25% + RX 2%; "
            "archival: ~12.3% = LRP 8.3% + RX 4%)"
        ),
    )

    ap_list = sub.add_parser("list", help="List archive contents")
    ap_list.add_argument("archive", help="Archive path")
    ap_list.add_argument("--password", help="Archive password")

    ap_info = sub.add_parser("info", help="Show archive information")
    ap_info.add_argument("archive", help="Archive path")
    ap_info.add_argument("--password", help="Archive password")

    # unseal
    ap_extract = sub.add_parser("unseal", help="Unseal files")
    ap_extract.add_argument("archive", help="Archive path")
    ap_extract.add_argument("--outdir", default=".", help="Output directory")
    ap_extract.add_argument("--password", help="Archive password")
    ap_extract.add_argument("paths", nargs="*", help="Specific archive paths to extract (files or directories)")
    ap_extract.add_argument("--quiet", help="limit outputs to summaries only", action="store_true")
    ap_extract.add_argument(
        "--exists",
        choices=["overwrite", "skip", "rename", "fail"],
        default="rename",
        help=(
            "What to do if a destination file exists: overwrite (truncate/replace), "
            "skip (do not extract that entry), rename (append ' (n)' before extension), or fail (abort). "
            "Default: rename"
        ),
    )

    ap_verify = sub.add_parser("verify", help="Verify archive integrity")
    ap_verify.add_argument("archive", help="Archive path")
    ap_verify.add_argument("--password", help="Archive password")

    ap_repair = sub.add_parser("repair", help="Attempt ECC repair")
    ap_repair.add_argument("archive", help="Archive path")
    ap_repair.add_argument("--password", help="Archive password")
    ap_repair.add_argument("--safe", action="store_true", help="Write repaired copy; do not modify input")
    ap_repair.add_argument("--output", help="Repaired copy path (implies --safe)")


    ap_rebuild = sub.add_parser(
        "rebuild",
        help="Rewrite archive by extracting to staging, verifying, and atomically swapping with a .bak backup",
    )
    ap_rebuild.add_argument("archive", help="Archive path")
    ap_rebuild.add_argument("--password", help="Archive password (required for encrypted archives)")

    ap_harden = sub.add_parser("harden", help="Append additional RX parity (verification runs first)")
    ap_harden.add_argument("archive", help="Archive path")
    ap_harden.add_argument("--extra-ppm", type=int, default=20000, help="Extra parity overhead in ppm (default 20000 = 2%). Verification runs first and the command aborts if the archive is dirty.")
    ap_harden.add_argument("--password", help="Archive password")
    ap_harden.add_argument(
        "--ecc-profile",
        choices=["lean", "balanced", "archival"],
        help=(
            "Profile to select extra parity (lean: +2%; balanced: +2%; archival: +4%) "
            "— overrides --extra-ppm"
        ),
    )

    ap_append = sub.add_parser("append", help="Append files to an existing archive (safe append segment)")
    ap_append.add_argument("archive", help="Archive path")
    ap_append.add_argument("inputs", nargs="+", help="Input files/directories to append")
    ap_append.add_argument("--password", help="Archive password (required if encrypted)")
    ap_append.add_argument(
        "--ecc-profile",
        choices=["lean", "balanced", "archival"],
        default="balanced",
        help="ECC profile for appended data (default: balanced)",
    )

    # scrub: verify many archives, optional repair and harden
    ap_scrub = sub.add_parser("scrub", help="Verify many archives; optional auto-repair and harden")
    ap_scrub.add_argument("paths", nargs="+", help="Archive paths or directories")
    ap_scrub.add_argument("--recursive", "-r", action="store_true", help="Recurse into directories")
    ap_scrub.add_argument("--jobs", "-j", type=int, default=4, help="Parallel jobs (default 4)")
    ap_scrub.add_argument("--password", help="Archive password (used for encrypted archives)")
    ap_scrub.add_argument("--repair", action="store_true", help="Attempt repair on failures (rebuild index if missing)")
    ap_scrub.add_argument("--safe", action="store_true", help="When repairing, keep source unchanged and write a repaired copy")
    ap_scrub.add_argument("--harden-extra", type=int, default=0, help="If >0, append this many ppm of RX after verify/repair")
    ap_scrub.add_argument("--json", action="store_true", help="Emit JSON result summary")
    ap_scrub.add_argument("--quiet", help="limit outputs to summaries only", action="store_true")
    


    args = ap.parse_args(argv)
    try:
        if args.cmd == "seal":
            cmd_seal(args.output, args.inputs, password=args.password, ecc_profile=args.ecc_profile, quiet=args.quiet)
        elif args.cmd == "unseal":
            cmd_unseal(args.archive, outdir=args.outdir, password=args.password, paths=args.paths, exists=args.exists)
        elif args.cmd == "list":
            cmd_list(args.archive, password=args.password)
        elif args.cmd == "info":
            cmd_info(args.archive, password=args.password)
        elif args.cmd == "verify":
            cmd_verify(args.archive, password=args.password)
        elif args.cmd == "repair":
            cmd_repair(args.archive, password=args.password, safe=args.safe, output=args.output)
        elif args.cmd == "rebuild":
            cmd_rebuild(args.archive, password=args.password)
        elif args.cmd == "harden":
            cmd_harden(args.archive, extra_ppm=args.extra_ppm, password=args.password, ecc_profile=args.ecc_profile)
        elif args.cmd == "append":
            cmd_append(args.archive, args.inputs, password=args.password, ecc_profile=args.ecc_profile)
        elif args.cmd == "scrub":
            success = cmd_scrub(
                args.paths,
                recursive=args.recursive,
                jobs=args.jobs,
                password=args.password,
                repair=args.repair,
                safe=args.safe,
                harden_extra=args.harden_extra,
                as_json=args.json,
                quiet=args.quiet
            )
            sys.exit(0 if success else 1)
        else:
            raise RuntimeError("Unknown command")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        msg = str(e)
        if "password required" in msg.lower():
            print("Error: Archive is encrypted. Provide --password.", file=sys.stderr)
        else:
            print(f"Error: {msg}", file=sys.stderr)
        sys.exit(2)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    except (AmberError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

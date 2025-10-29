from __future__ import annotations

import argparse
import os
import random
import sys
from typing import Optional

from amber.reader import ArchiveReader
from amber.errors import AmberError


def _flip_byte(path: str, offset: int, xor_val: int = 0xFF) -> None:
    if offset < 0:
        raise ValueError("Offset must be non-negative")
    with open(path, "r+b") as f:
        f.seek(offset)
        b = f.read(1)
        if not b:
            raise ValueError("Offset beyond end of file")
        f.seek(offset)
        f.write(bytes([b[0] ^ (xor_val & 0xFF)]))
        f.flush()
        os.fsync(f.fileno())


def cmd_by_offset(args: argparse.Namespace) -> None:
    _flip_byte(args.archive, args.offset, xor_val=args.xor)
    print(f"Flipped 1 byte at offset {args.offset}")


def cmd_first_symbol(args: argparse.Namespace) -> None:
    with ArchiveReader(args.archive, password=args.password) as r:
        sym = next((s for s in r.symbols if (args.include_parity or not s.is_parity)), None)
        if sym is None:
            raise ValueError("No suitable symbol found in archive")
        off = sym.offset + args.within
        _flip_byte(args.archive, off, xor_val=args.xor)
        print(f"Flipped 1 byte in symbol {sym.symbol_index} at archive offset {off}")


def cmd_symbol_index(args: argparse.Namespace) -> None:
    with ArchiveReader(args.archive, password=args.password) as r:
        idx = args.index
        if idx < 0 or idx >= len(r.symbols):
            raise ValueError(f"Symbol index out of range (0..{len(r.symbols)-1})")
        sym = r.symbols[idx]
        if not args.include_parity and sym.is_parity:
            raise ValueError("Selected symbol is parity; pass --include-parity to allow")
        if args.within < 0 or args.within >= sym.length:
            raise ValueError(f"--within must be within symbol length (0..{sym.length-1})")
        off = sym.offset + args.within
        _flip_byte(args.archive, off, xor_val=args.xor)
        print(f"Flipped 1 byte in symbol {idx} at archive offset {off}")


def cmd_random(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    flips = 0
    size = os.path.getsize(args.archive)
    with open(args.archive, "r+b") as f:
        for _ in range(args.count):
            pos = rng.randrange(0, size)
            f.seek(pos)
            b = f.read(1)
            if not b:
                continue
            f.seek(pos)
            f.write(bytes([b[0] ^ (args.xor & 0xFF)]))
            flips += 1
        f.flush()
        os.fsync(f.fileno())
    print(f"Flipped {flips} byte(s) at random offsets")


def main(argv: Optional[list[str]] = None) -> None:
    ap = argparse.ArgumentParser(prog="amber.corrupt", description="Corrupt Amber archives for testing")
    # Default mode (no subcommand): flip a byte in the first non-parity symbol
    ap.add_argument("default_archive", nargs="?", help="Archive path (default mode: flip in first non-parity symbol)")
    ap.add_argument("--default-within", dest="default_within", type=int, default=10, help="Byte offset within symbol (default 10)")
    ap.add_argument("--default-xor", dest="default_xor", type=int, default=0xFF, help="XOR mask to apply (default 0xFF)")
    ap.add_argument(
        "--default-include-parity",
        dest="default_include_parity",
        action="store_true",
        help="Allow corrupting a parity symbol in default mode",
    )
    ap.add_argument("--default-password", dest="default_password", help="Archive password if encrypted")

    sub = ap.add_subparsers(dest="cmd", required=False)

    p_off = sub.add_parser("by-offset", help="Flip one byte at an absolute archive offset")
    p_off.add_argument("archive", help="Path to .amber archive")
    p_off.add_argument("--offset", type=int, required=True, help="Absolute byte offset in archive")
    p_off.add_argument("--xor", type=lambda x: int(x, 0), default=0xFF, help="XOR mask to apply (default 0xFF)")
    p_off.set_defaults(func=cmd_by_offset)

    p_first = sub.add_parser("first-symbol", help="Flip a byte in the first symbol (non-parity by default)")
    p_first.add_argument("archive", help="Path to .amber archive")
    p_first.add_argument("--within", type=int, default=10, help="Byte offset within symbol (default 10)")
    p_first.add_argument("--xor", type=lambda x: int(x, 0), default=0xFF, help="XOR mask to apply (default 0xFF)")
    p_first.add_argument("--include-parity", action="store_true", help="Allow corrupting a parity symbol")
    p_first.add_argument("--password", help="Archive password if encrypted")
    p_first.set_defaults(func=cmd_first_symbol)

    p_sym = sub.add_parser("symbol", help="Flip a byte within a specific symbol index")
    p_sym.add_argument("archive", help="Path to .amber archive")
    p_sym.add_argument("--index", type=int, required=True, help="Symbol index (0-based)")
    p_sym.add_argument("--within", type=int, default=10, help="Byte offset within symbol (default 10)")
    p_sym.add_argument("--xor", type=lambda x: int(x, 0), default=0xFF, help="XOR mask to apply (default 0xFF)")
    p_sym.add_argument("--include-parity", action="store_true", help="Allow corrupting a parity symbol")
    p_sym.add_argument("--password", help="Archive password if encrypted")
    p_sym.set_defaults(func=cmd_symbol_index)

    p_rand = sub.add_parser("random", help="Flip N random bytes anywhere in the archive")
    p_rand.add_argument("archive", help="Path to .amber archive")
    p_rand.add_argument("--count", type=int, default=1, help="Number of random byte flips (default 1)")
    p_rand.add_argument("--seed", type=int, default=None, help="PRNG seed for reproducibility")
    p_rand.add_argument("--xor", type=lambda x: int(x, 0), default=0xFF, help="XOR mask to apply (default 0xFF)")
    p_rand.set_defaults(func=cmd_random)

    # Pre-dispatch: if argv starts with an archive path (not a subcommand), run default mode (random flip)
    subcommands = {"by-offset", "first-symbol", "symbol", "random"}
    if argv is None:
        argv = sys.argv[1:]
    if argv and (argv[0] not in subcommands) and (not argv[0].startswith("-")):
        # Minimal parser for default mode: flip N random bytes anywhere (no password required)
        dap = argparse.ArgumentParser(prog="amber.corrupt [default random]")
        dap.add_argument("archive")
        dap.add_argument("--count", type=int, default=1, help="Number of random byte flips (default 1)")
        dap.add_argument("--seed", type=int, default=None, help="PRNG seed for reproducibility")
        dap.add_argument("--xor", type=lambda x: int(x, 0), default=0xFF, help="XOR mask to apply (default 0xFF)")
        dargs = dap.parse_args(argv)
        ns = argparse.Namespace(archive=dargs.archive, count=dargs.count, seed=dargs.seed, xor=dargs.xor)
        try:
            cmd_random(ns)
        except (AmberError, OSError, ValueError, RuntimeError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)
        return

    # Fallback to full parser/subcommands
    args = ap.parse_args(argv)
    try:
        args.func(args)
    except (AmberError, OSError, ValueError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

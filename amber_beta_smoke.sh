#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${WORKDIR:-/tmp/amber-beta}"
PASS="${PASS:-beta-pass}"
KEEP_WORKDIR="${KEEP_WORKDIR:-0}"

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

if [[ -n "${AMBER_BIN:-}" ]]; then
  read -r -a AMBER_CMD <<<"$AMBER_BIN"
else
  AMBER_CMD=(cargo run --quiet --bin amber --)
fi

SRC_ROOT="$WORKDIR/src"
PLAIN_ARCHIVE="$WORKDIR/plain.amber"
COMP_ARCHIVE="$WORKDIR/compressed.amber"
ENC_ARCHIVE="$WORKDIR/encrypted.amber"
KEYFILE="$WORKDIR/keyfile.bin"
OUTDIR="$WORKDIR/out"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

run_amber() {
  "${AMBER_CMD[@]}" "$@"
}

expect_rc() {
  local expected="$1"
  shift
  set +e
  run_amber "$@"
  local rc=$?
  set -e
  if [[ "$rc" -ne "$expected" ]]; then
    fail "expected exit code $expected, got $rc: amber $*"
  fi
}

expect_verify_ok() {
  expect_rc 0 verify "$@"
}

expect_verify_fail() {
  expect_rc 1 verify "$@"
}

expect_verify_locked() {
  expect_rc 2 verify "$@"
}

cleanup() {
  if [[ "$KEEP_WORKDIR" != "1" ]]; then
    rm -rf "$WORKDIR"
  fi
}

trap cleanup EXIT

echo "==> Preparing test data in $WORKDIR"
rm -rf "$WORKDIR"
mkdir -p "$SRC_ROOT/sub"
printf 'hello\n' > "$SRC_ROOT/a.txt"
printf 'subfile\n' > "$SRC_ROOT/sub/c.txt"
dd if=/dev/urandom of="$SRC_ROOT/b.bin" bs=1M count=8 status=none
printf 'my-keyfile-material\n' > "$KEYFILE"

echo "==> Seal uncompressed-by-default archive"
run_amber seal "$SRC_ROOT" --output "$PLAIN_ARCHIVE"
expect_verify_ok "$PLAIN_ARCHIVE"

echo "==> Seal explicit compressed archive"
run_amber seal "$SRC_ROOT" --output "$COMP_ARCHIVE" --compress
expect_verify_ok "$COMP_ARCHIVE"

echo "==> Seal encrypted archive"
run_amber seal "$SRC_ROOT" --output "$ENC_ARCHIVE" --password "$PASS" --keyfile "$KEYFILE"
expect_verify_ok "$ENC_ARCHIVE" --password "$PASS" --keyfile "$KEYFILE"

echo "==> List / Info smoke"
run_amber list "$PLAIN_ARCHIVE"
run_amber info "$PLAIN_ARCHIVE"
run_amber list "$ENC_ARCHIVE" --password "$PASS" --keyfile "$KEYFILE"
run_amber info "$ENC_ARCHIVE" --password "$PASS" --keyfile "$KEYFILE"

echo "==> Unseal + compare plaintext archive"
mkdir -p "$OUTDIR/plain"
run_amber unseal "$PLAIN_ARCHIVE" --outdir "$OUTDIR/plain"
cmp "$SRC_ROOT/a.txt" "$OUTDIR/plain/src/a.txt"
cmp "$SRC_ROOT/sub/c.txt" "$OUTDIR/plain/src/sub/c.txt"

echo "==> Unseal + compare encrypted archive"
mkdir -p "$OUTDIR/encrypted"
run_amber unseal "$ENC_ARCHIVE" --outdir "$OUTDIR/encrypted" --password "$PASS" --keyfile "$KEYFILE"
cmp "$SRC_ROOT/a.txt" "$OUTDIR/encrypted/src/a.txt"
cmp "$SRC_ROOT/sub/c.txt" "$OUTDIR/encrypted/src/sub/c.txt"

echo "==> Append + harden"
printf 'append-one\n' > "$WORKDIR/add1.txt"
printf 'append-two\n' > "$WORKDIR/add2.txt"
run_amber append "$PLAIN_ARCHIVE" "$WORKDIR/add1.txt"
run_amber harden "$PLAIN_ARCHIVE" --extra-parity-percent 0.5
expect_verify_ok "$PLAIN_ARCHIVE"

run_amber append "$ENC_ARCHIVE" "$WORKDIR/add2.txt" --password "$PASS" --keyfile "$KEYFILE"
run_amber harden "$ENC_ARCHIVE" --extra-parity-percent 0.5 --password "$PASS" --keyfile "$KEYFILE"
expect_verify_ok "$ENC_ARCHIVE" --password "$PASS" --keyfile "$KEYFILE"

echo "==> Chunk corruption + repair (compressed archive)"
run_amber corrupt random-chunks --count 2 --seed 13 "$COMP_ARCHIVE"
expect_verify_fail "$COMP_ARCHIVE"
run_amber repair "$COMP_ARCHIVE"
expect_verify_ok "$COMP_ARCHIVE"

echo "==> Chunk corruption + safe repair (encrypted archive)"
run_amber corrupt random-chunks --count 1 --seed 19 --password "$PASS" --keyfile "$KEYFILE" "$ENC_ARCHIVE"
expect_verify_fail "$ENC_ARCHIVE" --password "$PASS" --keyfile "$KEYFILE"
run_amber repair "$ENC_ARCHIVE" --safe --password "$PASS" --keyfile "$KEYFILE"
ENC_REPAIRED="$WORKDIR/encrypted.repaired.amber"
[[ -f "$ENC_REPAIRED" ]] || fail "expected repaired encrypted copy at $ENC_REPAIRED"
expect_verify_ok "$ENC_REPAIRED" --password "$PASS" --keyfile "$KEYFILE"

echo "==> Rebuild + verify"
run_amber rebuild "$PLAIN_ARCHIVE"
expect_verify_ok "$PLAIN_ARCHIVE"
run_amber rebuild "$ENC_REPAIRED" --password "$PASS" --keyfile "$KEYFILE"
expect_verify_ok "$ENC_REPAIRED" --password "$PASS" --keyfile "$KEYFILE"

echo "==> Scrub"
run_amber scrub "$PLAIN_ARCHIVE" "$COMP_ARCHIVE" "$ENC_REPAIRED" --json --password "$PASS" --keyfile "$KEYFILE"

echo "==> Wrong-credential sanity checks"
expect_verify_locked "$ENC_ARCHIVE" --password wrong --keyfile "$KEYFILE"
BAD_KEYFILE="$WORKDIR/wrong-key.bin"
printf 'wrong-key-material\n' > "$BAD_KEYFILE"
expect_verify_locked "$ENC_ARCHIVE" --password "$PASS" --keyfile "$BAD_KEYFILE"

echo "PASS: Amber smoke test completed successfully."
echo "Artifacts:"
echo "  plain     : $PLAIN_ARCHIVE"
echo "  compressed: $COMP_ARCHIVE"
echo "  encrypted : $ENC_ARCHIVE"
echo "  source    : $SRC_ROOT"
echo "  outputs   : $OUTDIR"

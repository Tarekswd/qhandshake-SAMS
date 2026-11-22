#!/usr/bin/env bash
# Two-process demo over loopback TCP: one successful hybrid handshake, two expected failures.
# Usage: bash examples/demo.sh   (from the qhandshake/ directory, Linux or WSL)
set -euo pipefail
cargo build --release -q
BIN="${CARGO_TARGET_DIR:-target}/release/qh"
TMP=$(mktemp -d)
trap 'kill $SRV 2>/dev/null; rm -rf "$TMP"' EXIT

PUB=$("$BIN" keygen "$TMP/server.key")
WRONG=$("$BIN" keygen "$TMP/other.key")
"$BIN" server 127.0.0.1:4433 "$TMP/server.key" x25519mlkem768,x25519 2> "$TMP/server.log" &
SRV=$!
sleep 0.5

echo "== 1. hybrid handshake with the correct pinned key (expect success)"
"$BIN" client 127.0.0.1:4433 "$PUB" x25519mlkem768,x25519 "hello post-quantum" --require-pq

echo "== 2. wrong pinned server key (expect: server signature verification failed)"
if "$BIN" client 127.0.0.1:4433 "$WRONG" x25519mlkem768 "x"; then echo "UNEXPECTED SUCCESS"; exit 1; fi

echo "== 3. client offers only ML-KEM-768, server accepts hybrid/x25519 (expect: no common group)"
if "$BIN" client 127.0.0.1:4433 "$PUB" mlkem768 "x"; then echo "UNEXPECTED SUCCESS"; exit 1; fi

sleep 0.2
echo "== server log"
cat "$TMP/server.log"

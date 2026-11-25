#!/usr/bin/env bash
# Variable-latency scan over target x opt-level (stable toolchain): bash ct-audit/scan_matrix.sh <results_dir>
set -euo pipefail
OUT="${1:?results dir}"; mkdir -p "$OUT"
HERE="$(cd "$(dirname "$0")" && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/nextgen-target/ct-nostd}"
rustc --version > "$OUT/rustc.txt"
for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu thumbv7em-none-eabi thumbv6m-none-eabi; do
  for o in 0 1 2 3 s z; do
    (cd "$HERE/nostd" && CARGO_PROFILE_RELEASE_OPT_LEVEL=$o cargo build --release -q --target "$t")
    python3 "$HERE/scan_asm.py" "$CARGO_TARGET_DIR/$t/release/libct_nostd.a" > "$OUT/$t-O$o.txt"
    printf '%s\tO%s\t%s\n' "$t" "$o" "$(grep -P '^ct_' "$OUT/$t-O$o.txt" | awk -F'\t' '{printf "%s:%s ", $1, $3}')"
  done
done | tee "$OUT/matrix.tsv"

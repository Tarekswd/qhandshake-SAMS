#!/bin/bash
# Run every ct-harness target under Valgrind memcheck; one log per target and a summary of unique report sites.
#   bash ct-audit/run_vg.sh <out_dir> [cargo build flags...]
# Env: CARGO_TARGET_DIR (build dir), RUSTFLAGS (e.g. "-C opt-level=s"), TOOLCHAIN (e.g. +1.88.0).
# summary.tsv columns: errors = all memcheck reports; taint_checks = reports from the output checks in the harness
# (must be >= 1 for every target except the controls, otherwise the secret never reached the output);
# unique_sites = distinct code locations of secret-dependent jumps/addresses (the candidates to classify).
set -uo pipefail
out=$1; shift
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
(cd "$here/harness" && cargo ${TOOLCHAIN:-} build --release "$@" 2>"$out/build.log") || { echo "build failed, see $out/build.log"; exit 1; }
bin=${CARGO_TARGET_DIR:-$here/harness/target}/release/ct-harness
targets="control_leak control_clean mlkem_keygen mlkem_encaps mlkem_decaps mlkem_decaps_bad x25519 key_schedule"
printf "target\terrors\ttaint_checks\tunique_sites\n" > "$out/summary.tsv"
for t in $targets; do
  valgrind --error-exitcode=99 --num-callers=8 "$bin" "$t" > /dev/null 2> "$out/$t.log"
  n=$(grep -oP 'ERROR SUMMARY: \K[0-9]+' "$out/$t.log" | tail -1)
  c=$(grep -c 'during client check request' "$out/$t.log")
  # first in-program frame of every jump/address report ("at 0x..: fn (file:line)")
  grep -A1 -E 'Conditional jump|Use of uninitialised value' "$out/$t.log" | grep -oP 'at 0x[0-9A-F]+: \K.*' \
    | sed -E 's/\(in [^)]*\)//' | sort | uniq -c | sort -rn > "$out/$t.sites"
  printf "%s\t%s\t%s\t%s\n" "$t" "${n:-?}" "$c" "$(wc -l < "$out/$t.sites")" >> "$out/summary.tsv"
done
cat "$out/summary.tsv"

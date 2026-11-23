#!/bin/bash
# x86-64 configuration matrix (NOVELTY_PLAN.md E-Q1, first pass): rustc toolchain x opt-level.
#   bash ct-audit/matrix.sh <results_dir> [build_root=/mnt/d/nnp-build/ct]
# For each cell: build ct-harness, run every target under memcheck (run_vg.sh), keep summary.tsv + *.sites in
# <results_dir>/<toolchain>_O<level>/, delete the build directory. Cells already done are skipped (resume).
set -uo pipefail
res=$1 root=${2:-/mnt/d/nnp-build/ct}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$res"
for tc in 1.88.0 1.92 1.93.0 1.94.0 1.95.0 stable nightly; do
  for o in 0 1 2 3 s z; do
    cell="$res/${tc}_O$o"
    [ -s "$cell/summary.tsv" ] && continue
    log=$root/logs/${tc}_O$o
    rustc +$tc --version > /dev/null 2>&1 || { echo "$tc missing"; continue; }
    CARGO_TARGET_DIR=$root/build/${tc}_O$o CARGO_PROFILE_RELEASE_OPT_LEVEL=$o TOOLCHAIN=+$tc \
      bash "$here/run_vg.sh" "$log" > /dev/null
    mkdir -p "$cell"
    if [ -s "$log/summary.tsv" ]; then
      cp "$log/summary.tsv" "$log"/*.sites "$cell/"
    else
      echo "build failed" > "$cell/FAILED"; tail -20 "$log/build.log" >> "$cell/FAILED"
    fi
    rustc +$tc --version > "$cell/rustc.txt"
    rm -rf "$root/build/${tc}_O$o"
    echo "$(date -u +%H:%M:%S) $tc O$o: $(awk 'NR>1 && $1!~/^control/ {s=s $1 "=" $4 " "} END {print s}' "$cell/summary.tsv" 2>/dev/null)"
  done
done
# aggregate: unique secret-dependent sites per (cell, target)
python3 - "$res" <<'EOF'
import glob, os, sys
res = sys.argv[1]
rows = []
for f in sorted(glob.glob(f"{res}/*/summary.tsv")):
    cell = os.path.basename(os.path.dirname(f))
    for line in open(f).read().splitlines()[1:]:
        t, err, taint, sites = line.split("\t")
        rows.append((cell, t, err, taint, sites))
with open(f"{res}/matrix.tsv", "w") as out:
    out.write("cell\ttarget\terrors\ttaint_checks\tunique_sites\n")
    for r in rows:
        out.write("\t".join(r) + "\n")
print(f"{len(rows)} rows -> {res}/matrix.tsv")
EOF

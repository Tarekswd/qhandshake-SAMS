#!/usr/bin/env bash
# Single command to reproduce the QHandshake benchmark: bash benchmarks/run.sh [iterations]
# Writes results/<UTC timestamp>/{raw.csv,environment.txt,summary.md,handshake_latency.png}
set -euo pipefail
N="${1:-1000}"
OUT="results/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
cargo build --release -q --bin qh-bench
{
  echo "date_utc: $(date -u +%FT%TZ)"
  echo "iterations_per_config: $N (plus 20 warm-up, discarded)"
  echo "kernel: $(uname -srm)"
  echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)"
  echo "nproc: $(nproc)"
  echo "rustc: $(rustc --version)"
  echo "cpu_governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unavailable)"
  echo "crates:"; grep -A1 -E '^name = "(ml-kem|x25519-dalek|ed25519-dalek|hkdf|sha2|chacha20poly1305)"' Cargo.lock | grep -v -- '--' | paste - - | sed 's/^/  /'
} > "$OUT/environment.txt"
"${CARGO_TARGET_DIR:-target}/release/qh-bench" "$N" "$OUT/raw.csv"
PY="${PYTHON:-python3}"
"$PY" benchmarks/analyze.py "$OUT/raw.csv" "$OUT" || echo "analysis failed; raw data kept in $OUT/raw.csv"
echo "results in $OUT"

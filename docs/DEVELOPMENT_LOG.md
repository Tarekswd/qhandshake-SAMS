# Development Log

## 2026-11-22 - Phase 0, Phase 1 (QHandshake only), Phase 3 slice 1

### Phase 0: environment
- Host: Windows 11, AMD Ryzen 7 PRO 4750U (8C/16T), 15 GB RAM.
- Windows: Rust 1.89 (MSVC target, standalone install, no rustup), Python 3.14 + matplotlib 3.10, MSYS2 gcc 15.2,
  clang 21, cmake 3.31, OpenSSL 3.5.5, Docker 29.8 (daemon not running), no tshark.
- **Blocker found:** Windows Rust builds fail: no MSVC C++ build tools / Windows SDK, and Git Bash's coreutils
  `link` shadows `link.exe`. Fixing it needs a Visual Studio Build Tools install, which was not done.
- **Decision:** develop in WSL2 Ubuntu 24.04 (Rust 1.99.1 stable + nightly, cargo-fuzz, clippy, gcc, iproute2 `tc`).
  This also gives netem for later loss/RTT experiments. WSL has 7 GB RAM visible, no matplotlib (plots run on Windows Python).
  Build output goes to `~/.cache/nextgen-target/` on the Linux filesystem for speed.

### Phase 1: QHandshake design decisions
- Verified the hybrid construction against draft-ietf-tls-ecdhe-mlkem-05 / RFC 10024 and the IANA registry (fetched).
- Chose the RFC 10024 concatenation inside a TLS 1.3-style key schedule over X-Wing: it is what is deployed, and
  it keeps the testbed comparable to real TLS. X-Wing is recorded as an alternative.
- Own HKDF label prefix `qh01 ` for domain separation from real TLS.
- Server auth: pinned raw Ed25519 key, signature structured like TLS CertificateVerify. No PKI (out of scope).
- Sans-IO state machines so tests can act as a MITM.
- No HelloRetryRequest: the client sends all shares. Recorded as research question 1.

### Implemented
- `qhandshake` crate: codec, crypto (groups + key schedule), handshake state machines, record layer, TCP transport,
  alerts; `qh` CLI (keygen/server/client); `qh-bench`; fuzz target; `tools/kat.py`; `benchmarks/{run.sh,analyze.py}`.

### Tested
- 24 tests pass (`cargo test --release`); clippy `-D warnings` clean; `cargo fmt --check` clean.
- Two-process TCP demo (`examples/demo.sh`): success + wrong-key + no-common-group, alerts observed on both sides.
- Mutation check: removing the X25519 contributory check fails 1 test; removing signature verification fails 2 tests.
- libFuzzer `server_input`: 74,253 runs / 61 s, no crash, 405 edges covered (no seed corpus: weak).
- Benchmark n=1000: `results/20261122T063140Z/`. An earlier run (`20261122T062522Z`) predates the
  per-primitive rows and has no plot; it is kept as raw data and is consistent with the later run.

### What failed / surprised
- First client-side failure report was "failed to fill whole buffer" (server just closed). Added an Alert message;
  failures now report the reason on both sides.
- Absolute primitive timings look slow compared with commonly reported figures (not yet compared against a cited
  benchmark), e.g. X25519 scalar mult ~170 us, ML-KEM-768 keygen ~230 us. Not yet explained; suspects:
  mobile CPU power management under WSL2, default `target-cpu`. Relative comparisons are consistent (see attribution
  check in qhandshake/docs/RESEARCH.md).

### Incomplete
- QHandshake: formal model, HRR, netem experiments, seeded fuzzing, zeroization, paper draft, references marked
  "To verify" in docs/RESEARCH.md.
- CI workflow was written but had not been executed at this point (see later entry).
- PQ-QUIC, TrustPath and OrbitLink: not started.

### Next
1. PQ-QUIC stack survey: check which of quiche/BoringSSL, Quinn/rustls(+aws-lc-rs), MsQuic/OpenSSL 3.5 actually
   negotiate X25519MLKEM768 today. Build one client/server pair under netem.
2. Port the QHandshake share-strategy question (RQ1) into the shared netem harness.
3. Tamarin model of QHandshake.

## 2026-11-22 (later) - repository publication
- Zeroization: shared secrets, traffic secrets and Finished keys now in `Zeroizing` / `ZeroizeOnDrop` containers;
  capacity pre-reserved so the hybrid concatenation never reallocates. All 24 tests, clippy and fmt pass afterwards.
- `tools/kat.py` now exits non-zero if its vectors are not in `tests/kat.rs` (CI runs it).
- Added LICENSE-APACHE (fetched from apache.org) and LICENSE-MIT, matching `Cargo.toml`.
- CI moved into the repository (`.github/workflows/ci.yml`); pushed to github.com/Tarekswd/qhandshake-SAMS.
- Paper draft `docs/PAPER_DRAFT.md`: measured numbers only, TODO placeholders for unrun experiments.

## 2026-11-22 (later) - references verified
All references previously marked "To verify" were checked against primary sources (RFC Editor, IETF datatracker,
NIST, IACR ePrint/IEEE DOI). draft-ietf-tls-hybrid-design has been published as RFC 9954; docs updated. Not
re-checked: section numbers for RFC 7748 and for the FIPS 203 implicit-rejection algorithm.

## 2026-11-23 - ProVerif model
- Tamarin unavailable (maude needs sudo). Built ProVerif 2.05 from source via `opam source` + `./build -nointeract`
  (the opam package needs GTK headers for the GUI).
- formal/qhandshake.pv + formal/run.sh: all 5 expected results; the signature-removed mutant breaks secrecy and
  downgrade resistance. First checker version failed because ProVerif renames variables (ch -> ch_3); fixed.
- CI job builds ProVerif from the official tarball (checksum from opam metadata) and runs the model.
- Fixed docs/PAPER_DRAFT.md and docs/RESEARCH.md, which had been written as Windows-1252 ("Hövelmanns"); now UTF-8.

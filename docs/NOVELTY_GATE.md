# Novelty gate Q: compiler/target-induced constant-time violations in pure-Rust PQ crypto

Date: 2026-11-23. Verdict: **PASS (preliminary)**. Based on search results and targeted page reads, not a full reading
of every paper. A full read of CTGREP and Breaking Bad is still required before any written claim.

## Queries run
- "Rust constant-time compiler rustc LLVM timing side channel study cryptographic crates"
- "Breaking Bad how compilers break constant-time implementations AsiaCCS 2025 ... Rust"
- "RUSTSEC-2024-0344 curve25519-dalek timing variability"
- "RustCrypto ml-kem constant-time analysis compiler-induced branch valgrind ctgrind KyberSlash Rust"

## Closest prior work and how it differs
| Work | Scope | Difference |
|---|---|---|
| Schneider et al., *Breaking Bad*, AsiaCCS 2025, arXiv 2410.13489 | 8 C libraries (HACL*, Libsodium, Botan, BearSSL, BoringSSL, OpenSSL, WolfSSL, MbedTLS); riscv64, x86-64, i386 | C only; no Rust, no ML-KEM listed in the excerpt |
| Gerlach et al., *Do Compilers Break Constant-time Guarantees?*, FC 2025 (CISPA) | gcc, clang, icc, aocc, tcc, CompCert, zig cc; OpenSSL, BearSSL, mbedTLS, wolfSSL, libsodium, CTTK; x86 | No Rust, no PQ (page read 2026-11-23) |
| CTGREP, ePrint 2026/2653 | 7 C libraries, 3 Clang versions, 6 targets, pass-level differential analysis; ML-KEM motivating example | Clang/C only (its own stated limitation) |
| KyberSlash (Bernstein et al. 2024/25) | Patched Valgrind for variable-latency instructions; >1000 C implementations (SUPERCOP) | C; division-specific |
| RUSTSEC-2024-0344 | curve25519-dalek `Scalar29::sub`/`Scalar52::sub`: LLVM inserted a branch on a mask (2024-06-18) | Single bug, found individually |
| CVE-2026-23519 / RUSTSEC-2026-0003 | RustCrypto `cmov` < 0.4.4 on thumbv6m (Cortex-M0) (published 2026-01-15) | Single bug, single target. Shows the class is live in RustCrypto |
| Trail of Bits, LLVM constant-time support (blog 2025-12-02, llvm-project PR 166702) | Compiler mitigation (ct select builtins) | Mitigation, not a measurement of Rust crates; relevant as a "fix" baseline |
| Cryspen libcrux | Verified Rust ML-KEM (source-level) | Does not measure emitted binaries across rustc and targets |

## Verdict and narrowing
No systematic rustc x version x target x configuration study of pure-Rust ML-KEM/X25519 was found. The two Rust
advisories (2024, 2026) show this is a real bug class in exactly these ecosystems, which strengthens motivation. Target
list must include thumbv6m/thumbv7em (embedded, where the cmov bug was), not only desktop targets.

Constraint (user decision 2026-11-23): no bare-metal Linux machine, so no dudect confirmation. Findings are reported as
"Valgrind/static findings, exploitability unconfirmed".

## Still to do before claims
- Read CTGREP §6/§9 and Breaking Bad §5-6 fully; check the RustCrypto/KEMs and dalek issue trackers.
- Search the RustSec database for every advisory with category `crypto-failure` and keyword "timing".

# ct-audit: compiler/target-induced constant-time violations (NOVELTY_PLAN.md section 1)

Method: ctgrind-style secret poisoning (Langley 2010). `harness/` marks secret inputs as undefined for Valgrind
memcheck. memcheck then reports every conditional jump ("Conditional jump or move depends on uninitialised
value") and every memory address ("Use of uninitialised value") that depends on a secret. Not covered:
variable-latency instructions such as division (KyberSlash class); that needs a patched Valgrind or the planned
disassembly scan. No timing measurements: there is no bare-metal machine, so findings are reported as
"secret-dependent control flow/addresses in the binary", without an exploitability claim.

Every run is self-checked:
- `control_leak` must give exactly 1 site and `control_clean` 0 sites;
- every other target must have `taint_checks >= 1`, meaning its output was still secret before it was
  declassified. Without that, a zero would only mean the secret never reached the code.

## Run
    bash ct-audit/run_vg.sh <out_dir>            # one configuration
    bash ct-audit/matrix.sh <results_dir>        # rustc toolchain x opt-level, x86-64

## Baseline: rustc 1.99.1 stable, release (opt-level 3), x86-64, 2026-11-23
| target | sites | classification |
|---|---|---|
| control_leak / control_clean | 1 / 0 | controls behave as required |
| mlkem_keygen | 2 (`ml_kem::algebra::rej_uniform`, algebra.rs:68, :73) | benign: rejection sampling of the public matrix A from rho. rho is derived from the poisoned seed, so it is tainted, but it is public (part of the encapsulation key) |
| mlkem_encaps (secret m) | 0 | clean |
| mlkem_decaps, mlkem_decaps_bad (secret s, z; valid and tampered ct) | 0 | clean, including the implicit-rejection path |
| x25519 (secret scalar) | 0 | clean |
| key_schedule (secret shared secret) | 1 (`map_err` in `verify_finished`) | benign: the Finished verdict is public by design (the MAC comparison itself is constant time) |

Crate versions: ml-kem 0.3.4, x25519-dalek 3.0.0 (curve25519-dalek 5.0.0), hkdf 0.13, hmac 0.13, sha2 0.11.

## Triaged reports
- **x25519 at opt-level 0 and 1 (rustc 1.88.0 and stable 1.99.1): 1 site, `MontgomeryPoint::mul_bits_be`
  (montgomery.rs:194). FALSE POSITIVE.** Disassembly at -O1: `setb %al` stores the secret scalar bit (0/1) as the
  `Some` payload of the bit iterator's `Option<bool>`, and `None` is the niche value 2 (`mov $0x2,%al`). The
  flagged `cmp $0x2,%al; je` is the loop's `next()` test: "is it None?". Its outcome is the same for bit 0 and
  bit 1, so it does not leak, but memcheck reports it because the compared byte is partly secret. Line 194 is
  the line-table attribution (the `debug_assert!` there is compiled out). At -O3 LLVM separates the loop test from
  the bit and the report disappears. This is a Rust-specific false-positive pattern (niche-encoded
  `Option<bool>`/`Option<u8>` holding a secret): triage must check whether the compared constant lies outside
  the secret's value range.

- **x25519 at opt-level z (rustc 1.88.0, 1.92, 1.93.0, 1.94.0, 1.95.0, stable; not nightly 1.101.0): same site,
  same FALSE POSITIVE.** Disassembly of the 1.95.0 -Oz build: the bit iterator's `next_back()` is an outlined
  call returning `Option<bool>` in `%al`. The flagged `cmp $0x2,%bpl; je` is the "is it None?" test, and the
  secret bit is used only in `xor %bpl,%bl`, which feeds the constant-time `conditional_swap`. Nightly -Oz emits
  `setb` without the niche compare, so no report.
- **key_schedule at opt-level 0, every toolchain: `<Hmac<Sha256> as Mac>::verify_slice` (digest 0.11.3,
  mac.rs:145). BENIGN.** Line 145 is `if choice.into() { Ok(()) } else { Err(MacError) }`, the branch on the result
  of the constant-time `ct_eq`. That is the public Finished verdict, the same class as the `map_err` report;
  verify_slice is not inlined at -O0.

## x86-64 configuration matrix (E-Q1 first pass, 2026-11-25)

`ct-audit/matrix.sh`: 7 toolchains (1.88.0, 1.92, 1.93.0, 1.94.0, 1.95.0, stable 1.99.1, nightly 1.101.0) x 6
opt-levels (0, 1, 2, 3, s, z) = 42 cells, 8 targets each. Results are in
`results/ct-matrix-x86_64-20261123/` (`matrix.tsv` plus per-cell `*.sites`).

| target | cells with reports | sites | verdict |
|---|---|---|---|
| control_leak | 42/42 | 1 | positive control fires in every cell |
| control_clean | 0/42 | 0 | negative control clean |
| mlkem_encaps, mlkem_decaps, mlkem_decaps_bad | 0/42 | 0 | clean (implicit rejection included) |
| mlkem_keygen | 42/42 | `rej_uniform` (algebra.rs:68, :73) | benign: public matrix A from rho |
| key_schedule | 42/42 | `verify_finished` verdict; `verify_slice` at -O0 | benign: public verdict |
| x25519 | 20/42 (O0, O1 everywhere; Oz except nightly) | `mul_bits_be` (montgomery.rs:194) | false positive: `Option<bool>` niche test |

**Result: no compiler- or opt-level-induced secret-dependent branch or memory access** in ml-kem 0.3.4 or
x25519-dalek 3.0.0 on x86-64, across this matrix. This is a negative result, and it is limited to:

- Valgrind memcheck's definedness tracking, i.e. branches and addresses. Variable-latency instructions such as
  division are not covered.
- One target (x86_64-unknown-linux-gnu) and default target features.
- The harness's code paths.

## Variable-latency scan across targets (Q-6, 2026-11-25)

Valgrind cannot run thumbv6m/thumbv7em binaries and does not see variable-latency instructions. `nostd/` exposes
the same entry points as the harness (`ct_mlkem_keygen/encaps/decaps`, `ct_x25519`) as a `no_std` staticlib, plus
the positive control `ct_control_div` (a u64 division). `scan_asm.py` disassembles the archive with relocations
(`llvm-objdump -dr`), follows the call graph from each entry and flags divide instructions (`div`/`idiv`,
`udiv`/`sdiv`) and divide libcalls (`__aeabi_*div*`, `__udivmod*` ...). Machine-outliner symbols
(`OUTLINED_FUNCTION_n`) are qualified by object file; without that, a same-named fragment from `f64` parsing made a
float division look reachable from x25519 at thumbv7em -Oz (a scanner false positive, fixed).

    bash ct-audit/scan_matrix.sh results/ct-scan-asm-20261125    # 4 targets x 6 opt-levels, stable 1.99.1

Results: `results/ct-scan-asm-20261125/` (`matrix.tsv` plus one file per cell). Targets: x86_64-unknown-linux-gnu,
aarch64-unknown-linux-gnu, thumbv7em-none-eabi, thumbv6m-none-eabi (Cortex-M0: no hardware divide, so every
division is an `__aeabi_uidiv*` call). Crate versions as the harness; cmov 0.5.4 (after the CVE-2026-23519 fix).

| entry | flagged cells | flagged functions | verdict |
|---|---|---|---|
| ct_control_div | 24/24 | the division itself | positive control fires everywhere |
| ct_x25519 | 0/24 | none | clean |
| ct_mlkem_* | O0/O1/Os/Oz everywhere; thumbv6m at every level | slice `Chunks*` iterator `size`/`size_hint`/`zip`, `chunks_exact` | benign: slice length / chunk size, both public |
| | | `sponge_cursor::absorb_u64_le`, `sha3::Sha3_512::update`, `shake::ShakeReader::read` | benign: message or buffer length / sponge rate (sponge-cursor-0.1.0 lib.rs `data.chunks_exact(RATE)`) |
| | | `keccak::backends::soft::keccak_p` | benign: `(x + 4) % 5`, `(x + 1) % 5`, `(x + 2) % 5` on the loop counter (keccak-0.2.2 soft.rs:78-79, 101-102) |
| | | `ml_kem::algebra::rej_uniform` | benign: `bytes.chunks_exact(3)` on the public XOF stream (algebra.rs:60) |
| | | `<usize as Display>::fmt` | benign: panic-message formatting |

**Result: no division on secret data** is reachable from ML-KEM-768 or X25519 on any of the 4 targets x 6
opt-levels. Every flagged division divides a length or a loop index. Limits: static reachability over-approximates
(it includes panic paths) and cannot see indirect calls; divisions are the only variable-latency class scanned
(multiplication is assumed constant time; Cortex-M3 long multiply is reported to be variable-latency, not checked);
operand classification is by reading the source, not by taint tracking. ShakeReader/Sha3_512 sites were
classified from the shared `chunks`/rate pattern, not line by line.

Next: Valgrind on aarch64 under QEMU user mode for branches/addresses (the scan above covers only divisions), and
a multiply-latency check for Cortex-M3.

Known gap: `qhandshake::crypto::x25519` branches on `was_contributory()`, which reveals only whether the shared
secret is all zero (an invalid, public condition). It is not exercised here because `server_respond` and
`client_finish` are crate-private and take randomness from getrandom.

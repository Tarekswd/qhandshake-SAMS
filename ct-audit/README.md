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

Next: other targets (aarch64, thumbv7em/thumbv6m, where CVE-2026-23519 was found) and a variable-latency
instruction check.

Known gap: `qhandshake::crypto::x25519` branches on `was_contributory()`, which reveals only whether the shared
secret is all zero (an invalid, public condition). It is not exercised here because `server_respond` and
`client_finish` are crate-private and take randomness from getrandom.

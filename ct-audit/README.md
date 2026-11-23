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

Known gap: `qhandshake::crypto::x25519` branches on `was_contributory()`, which reveals only whether the shared
secret is all zero (an invalid, public condition). It is not exercised here because `server_respond` and
`client_finish` are crate-private and take randomness from getrandom.

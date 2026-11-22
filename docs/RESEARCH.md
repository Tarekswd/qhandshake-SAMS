# QHandshake - Research Position (Phase 1, initial)

## Honest novelty statement
**QHandshake v1 contains no novel cryptography and no novel protocol mechanism.** Its key exchange is the
standardized X25519MLKEM768 construction inside a TLS 1.3-structured key schedule. Its value today is as a
*small, fully instrumented testbed* in which every byte and microsecond of hybrid key establishment can be
attributed, and in which attacks can be scripted against sans-IO state machines.

A research contribution must come from one of the open questions below, backed by experiments or a formal model.

## Reference status
"Verified" means the source was fetched and checked during development (2026-11-22). Everything else must be
checked before it is cited in a paper.

| Reference | What we use it for | Status |
|---|---|---|
| RFC 10024 / draft-ietf-tls-ecdhe-mlkem-05 (Kwiatkowski, Kampanakis, Westerbaan, Stebila; published 26 May 2026), https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem | Hybrid share layout (1216 / 1120 bytes), secret order mlkem\|\|x25519 | Verified |
| IANA TLS Supported Groups registry, https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml | Codepoints 29, 513, 4588; RFC 9846 listed as current TLS 1.3 reference | Verified |
| RFC 8446 (TLS 1.3) / RFC 9846 | Key schedule, framing, alerts | Structure followed; text not re-read this session |
| draft-ietf-tls-hybrid-design | Security argument for concatenation combiner in TLS key schedule | **To verify** (version, exact claim) |
| FIPS 203 (ML-KEM) | Encapsulation-key input check, implicit rejection | **To verify** section numbers |
| X-Wing KEM (draft-connolly-cfrg-xwing-kem) | Alternative standalone hybrid KEM combiner | **To verify**; `x-wing` crate 0.1.1 exists on crates.io (checked) |
| RFC 7748 (X25519), RFC 7250 (raw public keys), RFC 5869 (HKDF) | Primitives | **To verify** section references |

## Candidate research questions (not yet answered)
1. **Share-strategy cost model.** Sending shares for every offered group (this prototype) versus a single share plus
   HelloRetryRequest (TLS practice): quantify the byte/CPU vs round-trip trade-off across RTT and loss. Hypothesis:
   above some RTT threshold, speculative multi-share wins even with ML-KEM's 1.2 KB shares. Needs: HRR implementation,
   netem experiments (shared methodology with PQ-QUIC).
2. **Formal analysis of the downgrade argument.** Model QHandshake in Tamarin with a CRQC adversary that can break
   X25519/Ed25519 at chosen times; check which secrecy/authentication lemmas survive. Mostly a replication of known
   TLS hybrid results - valuable as a teaching artefact, novel only if it covers a gap in existing models
   (requires literature check).
3. **Server-side DoS asymmetry.** One ClientHello costs the server ~0.6 ms of CPU (encaps + X25519 + sign, measured).
   Evaluate stateless-cookie designs for PQ handshakes. Needs a literature check: this may already be covered by
   work on PQ TLS/DTLS DoS.

## Measured results so far (see results/20261122T063140Z/)
Measured on AMD Ryzen 7 PRO 4750U, WSL2 Linux 6.6, rustc 1.99.1, release build, n=1000 per configuration.
Absolute primitive timings look slow compared with commonly reported figures for these primitives (not yet
compared against a cited benchmark); likely platform effects (mobile CPU under WSL2, no `target-cpu=native`). Only
relative comparisons should be drawn from this data.

| Configuration | Handshake bytes (c->s / s->c) | In-process CPU, median | Loopback TCP to first app byte, median |
|---|---|---|---|
| X25519 | 115 / 178 | 705 us | 1707 us |
| ML-KEM-768 | 1267 / 1234 | 1082 us | 2209 us |
| X25519MLKEM768 | 1299 / 1266 | 1529 us | 2698 us |

Attribution check: hybrid minus X25519 in-process (~855 us mean) matches the sum of separately measured ML-KEM keygen +
encaps + decaps means (~838 us), so the protocol logic adds no unexplained overhead.

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

| Reference | What we use it for | Status (2026-11-22) |
|---|---|---|
| RFC 10024 / draft-ietf-tls-ecdhe-mlkem-05 (Kwiatkowski, Kampanakis, Westerbaan, Stebila; 26 May 2026), https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem | Hybrid share layout (1216 / 1120 bytes), secret order mlkem\|\|x25519 | Verified |
| IANA TLS Supported Groups registry, https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml | Codepoints 29, 513, 4588 | Verified |
| RFC 9954, *Hybrid Key Exchange in TLS 1.3* (Stebila, Fluhrer, Gueron; July 2026, Informational), formerly draft-ietf-tls-hybrid-design-16, https://www.rfc-editor.org/rfc/rfc9954.html | Concatenated shared secrets fed into the TLS 1.3 key schedule; Section 3.3. Its security considerations relate this to the dual-PRF combiner analysis and to NIST SP 800-56C. | Verified (the draft is now an RFC) |
| RFC 8446, *TLS 1.3* (Rescorla, Aug 2018), https://www.rfc-editor.org/info/rfc8446 | Key schedule (Section 7.1); "the Finished MAC (and, where present, the signature) prevents downgrade attacks" (Appendix E.1), which our mutation test reproduces | Verified |
| FIPS 203 (NIST, 13 Aug 2024), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf | Encapsulation-key type check and modulus check (eq. 7.1) required before ML-KEM.Encaps | Verified (implicit-rejection algorithm number not re-checked) |
| X-Wing, draft-connolly-cfrg-xwing-kem-11 (Connolly, Schwabe, Westerbaan; ISE stream, updated 2026-09-23), https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ | Alternative standalone hybrid KEM (SHA3-256 combiner, ML-KEM ciphertext not hashed) | Verified |
| Connolly, Hövelmanns, Hülsing, Kousidis, Meijers, *Starfighters: On the General Applicability of X-Wing*, IEEE S&P 2026, doi:10.1109/SP63933.2026.00143, https://eprint.iacr.org/2025/1397 | Proves C2PRI for Fujisaki-Okamoto variants, making the QSF combiner applicable | Verified (pointer originally from PHOENIX-PQ) |
| RFC 7748 (Langley, Hamburg, Turner, Jan 2016), https://www.rfc-editor.org/rfc/rfc7748.html | Check whether the X25519 output is all-zero and abort | Verified wording (section number in code comments not re-checked) |
| RFC 7250 (Wouters et al., June 2014), raw public keys in TLS/DTLS | Pinned raw-key authentication model | Verified |
| RFC 5869 (Krawczyk, Eronen, May 2010), HKDF | Key derivation | Verified |

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

## RQ2 status (2026-11-23)
A ProVerif 2.05 model (formal/qhandshake.pv) shows, symbolically and with X25519 assumed broken: hybrid-key secrecy,
and (injective) agreement on the exact ClientHello and chosen group, i.e. downgrade resistance. Removing the
signature check breaks both, which matches the Rust mutation test. This replicates known TLS 1.3 hybrid reasoning
for our protocol; it is not a novel result.

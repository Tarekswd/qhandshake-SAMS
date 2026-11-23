# QHandshake: An Instrumented Testbed for Attributing the Cost of Hybrid Post-Quantum Key Establishment

*Working draft. Sections marked **[TODO-EXPERIMENT]** describe experiments that have not been run; no numbers are given for them.
Every number that is given comes from `results/20261122T063140Z/` (raw CSV + environment file).*

## Abstract
Hybrid key establishment combining X25519 with ML-KEM-768 is being deployed in TLS 1.3 (RFC 10024). Production stacks
make it hard to attribute handshake cost to individual operations or to script attacks against the state machine.
We present QHandshake, a deliberately minimal, TLS 1.3-structured, server-authenticated 1-RTT handshake built entirely
from existing primitives, with sans-IO state machines, a strict codec, and adversarial tests. On a mobile x86-64 CPU
the hybrid configuration costs 2565 handshake bytes versus 293 for X25519 alone. Median in-process handshake CPU time
is 1529 us versus 705 us. The difference is fully explained by the separately measured ML-KEM operations.
**[TODO-EXPERIMENT]** results under RTT and loss, and the share-strategy comparison (RQ1).

## 1. Introduction
- Motivation: harvest-now-decrypt-later, so confidentiality has to move to PQ key exchange before a CRQC exists.
- Problem: protocol-level cost and failure behaviour of hybrid key exchange are usually measured inside large stacks,
  where attribution is hard.
- Contribution (claimed only to the extent supported in this draft):
  1. A small open testbed with a written spec, threat model and reproducible benchmarks (done).
  2. Byte and CPU attribution of hybrid vs single-algorithm key exchange on one platform (done, single platform).
  3. **[TODO-EXPERIMENT]** Share-strategy cost model (speculative multi-share vs HelloRetryRequest) under netem.
  4. **[TODO]** Symbolic model (Tamarin) of downgrade resistance with a time-of-break CRQC adversary.

## 2. Background and related work
- TLS 1.3 key schedule (RFC 8446; RFC 9846 per IANA registry).
- X25519MLKEM768 (RFC 10024 / draft-ietf-tls-ecdhe-mlkem-05, verified).
- Combiner security: RFC 9954 (concatenation in the TLS 1.3 key schedule; dual-PRF argument); X-Wing
  (draft-connolly-cfrg-xwing-kem-11) and its QSF/C2PRI analysis (Starfighters, IEEE S&P 2026). Verified; see docs/RESEARCH.md.
- Prior PQ-TLS measurement: Paquin, Stebila, Tamvada, *Benchmarking Post-Quantum Cryptography in TLS*, PQCrypto 2020
  (ePrint 2019/1447), measured under emulated network conditions. Verified.

## 3. Design
See `spec/PROTOCOL.md`. Summary: ClientHello carries a share per offered group; the server selects by its own
preference; it then signs H(CH||SH) with a pinned Ed25519 key; Finished MACs cover the full transcript; HKDF labels use
the prefix "qh01 " to keep keys separate from TLS. Deliberate omissions (encrypted handshake, PKI, HRR, PSK) are listed
in spec section 9.

## 4. Security model
See `docs/THREAT_MODEL.md`. Dolev-Yao network attacker plus a future CRQC (harvest-now-decrypt-later). Authentication is
classical (Ed25519). Claims are supported by tests, not by proof:
downgrade by stripping offers, wrong key, tampered messages, replay, low-order X25519 points, invalid ML-KEM keys, and
state-machine confusion. A mutation check showed that removing signature verification is detected by the tests.
Removing it does not stop the passive offer-stripping attack, because the Finished MAC still catches that attack.
The signature is what is needed against an attacker who replaces key shares.

## 5. Implementation
Rust 2024; ml-kem 0.3.4, x25519-dalek 3.0.0, ed25519-dalek 3.0.0, hkdf 0.13.0, sha2 0.11.1, chacha20poly1305 0.11.0.
No cryptographic primitive is implemented by us. Secrets are held in zeroize-on-drop containers. 24 automated
tests, including a key-schedule known-answer test checked against an independent Python implementation and property
tests of the decoder. libFuzzer smoke run: 74,253 executions, no crash.

## 6. Methodology
- Platform: AMD Ryzen 7 PRO 4750U, WSL2 Linux 6.6.87, rustc 1.99.1, release build. CPU governor not controllable
  under WSL2.
- Per configuration: 20 warm-up runs discarded, then n=1000. Metrics: per-primitive time; in-process handshake
  CPU time split by party; loopback TCP time from connect() to the first echoed application byte; handshake bytes.
- Statistics: mean, median, sd, normal-approximation 95% CI of the mean, p5/p95/p99.
- Reproduce: `bash benchmarks/run.sh 1000`.

## 7. Results (measured)

| Configuration | Bytes c->s / s->c | In-process CPU median (us) | Loopback TCP median (us) |
|---|---|---|---|
| X25519 | 115 / 178 | 705 | 1707 |
| ML-KEM-768 | 1267 / 1234 | 1082 | 2209 |
| X25519MLKEM768 | 1299 / 1266 | 1529 | 2698 |

Attribution: hybrid minus X25519 in-process mean is about 855 us. The separately measured mean ML-KEM keygen +
encaps + decaps is about 838 us. Primitive times on this platform are high in absolute terms, for example X25519
scalar multiplication at about 170 us. The cause is not yet determined, so only relative comparisons are drawn.

**[TODO-EXPERIMENT]** Repeat on bare-metal Linux with a fixed CPU governor and `target-cpu=native`.
**[TODO-EXPERIMENT]** netem grid: RTT {1, 20, 80, 200} ms x loss {0, 1, 5} %, n>=200 per cell.

## 8. Discussion and limitations
Single platform; WSL2 timing noise; no identity hiding; no client authentication; classical authentication only; no
formal proof; the fuzzing so far is a smoke test; the dependency crates are recent releases whose audit status has
not been checked.

## 9. Future work
HRR plus the share-strategy study (RQ1); Tamarin model (RQ2); stateless-cookie DoS mitigation (RQ3); shared netem
harness with the PQ-QUIC project.

## 10. Conclusion
**[TODO after RQ1/RQ2 results]**

## References
Only verified references are listed; full table in `docs/RESEARCH.md`.
1. K. Kwiatkowski, P. Kampanakis, B. Westerbaan, D. Stebila. *Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLSv1.3*,
   draft-ietf-tls-ecdhe-mlkem-05, 26 May 2026 (RFC 10024). https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem
2. IANA, *Transport Layer Security (TLS) Parameters*, Supported Groups registry. https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
3. D. Stebila, S. Fluhrer, S. Gueron. *Hybrid Key Exchange in TLS 1.3*, RFC 9954, July 2026.
4. E. Rescorla. *The Transport Layer Security (TLS) Protocol Version 1.3*, RFC 8446, August 2018.
5. NIST. *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, FIPS 203, August 2024.
6. D. Connolly, P. Schwabe, B. Westerbaan. *X-Wing: general-purpose hybrid post-quantum KEM*, draft-connolly-cfrg-xwing-kem-11, 2026.
7. D. Connolly, K. Hövelmanns, A. Hülsing, S. Kousidis, M. Meijers. *Starfighters: On the General Applicability of X-Wing*, IEEE S&P 2026, doi:10.1109/SP63933.2026.00143.
8. C. Paquin, D. Stebila, G. Tamvada. *Benchmarking Post-Quantum Cryptography in TLS*, PQCrypto 2020, ePrint 2019/1447.

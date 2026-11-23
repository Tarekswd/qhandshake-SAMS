# Symbolic model (ProVerif)

`qhandshake.pv` models QHandshake v1 for ProVerif 2.05: unbounded sessions, one pinned server key, hybrid and
classical-only clients, and an attacker who controls the network **and** learns every client's X25519 secret
(X25519 assumed broken by a quantum computer). Primitives are ideal; the key schedule is abstracted to
`kdf(ss_mlkem, ss_x25519, H(CH, SH))`.

```bash
PROVERIF=/path/to/proverif bash formal/run.sh   # ~3 s; exits non-zero on any unexpected result
```

| Query | Model | Mutant without server-signature check |
|---|---|---|
| Hybrid session secret stays secret although X25519 is broken | true | **false** |
| Classical-only session secret (sanity check that the quantum attacker is effective) | false (leaks), as expected | false |
| Client accepts (CH, group) => server chose that group for that exact CH (downgrade resistance) | true | **false** |
| Same, injective | true | **false** |
| Hybrid handshake is reachable (model is not vacuous) | reachable | reachable |

Limits: a symbolic abstraction of the specification, not a proof about the Rust code; no HelloRetryRequest, no
compromise of the server's long-term key, no timing or implementation attacks. ML-KEM is modelled as an ideal KEM.
Building ProVerif without its GUI: `opam source proverif && cd proverif.2.05 && ./build -nointeract`.

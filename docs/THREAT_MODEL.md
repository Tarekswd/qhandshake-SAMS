# QHandshake - Threat Model and Security Analysis

**This is not a security proof of the implementation.** A symbolic ProVerif model of the specification exists
(formal/README.md): hybrid-key secrecy with X25519 broken and downgrade resistance hold, and both fail when the
server-signature check is removed.
Everything below is either (a) an argument by reference to TLS 1.3's design, or (b) backed by a named test.

## Assets
Application-data confidentiality and integrity; the server's long-term Ed25519 key; session keys.

## Attacker (Dolev-Yao network attacker)
- Reads, drops, reorders, replays, modifies and injects any message on the wire.
- May run its own clients and servers, and may hold its own valid Ed25519 keys.
- **Harvest-now-decrypt-later:** may record traffic today and later obtain a cryptographically relevant
  quantum computer (CRQC) that breaks X25519 and Ed25519.
- Does NOT: compromise endpoint memory, break SHA-256/HKDF/ChaCha20-Poly1305, or exploit side channels
  (side channels are out of scope; we rely on the constant-time claims of the dependency crates).

## Trust boundaries
1. Network bytes -> `codec::Message::decode` (untrusted input boundary).
2. Decoded fields -> group selection and key-share validation (`crypto::server_respond`, `client_finish`).
3. Pinned server public key: supplied out of band by the operator; trusted.
4. OS RNG (`getrandom`): trusted.

## Security goals and how they are supported

| Goal | Mechanism | Evidence in this repo |
|---|---|---|
| Server authentication | Ed25519 sig over H(CH\|\|SH) with pinned key | `wrong_pinned_key_fails`; mutation check (sig removal is caught) |
| Downgrade resistance | Server signs transcript incl. full ClientHello offer | `downgrade_by_stripping_hybrid_share_is_detected` |
| Policy enforcement | `require_pq` client policy | `require_pq_rejects_classical_only_server` |
| Transcript integrity | Finished MACs over full transcript | `tampered_server_finished_fails`, `tampered_server_hello_share_fails` |
| Replay of handshake flights | Fresh server random + ephemeral keys | `replayed_client_flight_is_rejected_by_fresh_server` |
| Record replay/tamper | AEAD with sequence-number nonces | `record_replay_and_tamper_rejected` |
| Malformed-input robustness | Strict decoder, size bound, poisoning state machine | proptest (2000 cases x 3), truncation test, 60 s libFuzzer smoke run |
| Invalid key material | X25519 contributory check, FIPS 203 ek check, exact lengths | `x25519_low_order_point_rejected`, `invalid_mlkem_encapsulation_key_rejected`, `wrong_share_lengths_rejected` |
| State-machine confusion | Explicit (state, message) match; terminal Failed | `out_of_order_message_poisons_state_machine`, `server_selecting_unoffered_group_is_rejected` |

### Observation from mutation testing
With signature verification removed (mutant 2), the passive "strip hybrid from ClientHello" attack is still
detected - by the Finished MAC, because the attacker did not change the key shares and so cannot compute
`s_hs`. The signature is what stops an attacker who **replaces** the key shares (a full MITM). The tests
`downgrade_*` and `wrong_pinned_key_fails` assert `BadSignature` specifically, so they fail under that mutant.

## Post-quantum properties - stated precisely
- **Confidentiality against harvest-now-decrypt-later:** for `MLKEM768` and `X25519MLKEM768`, session keys depend
  on the ML-KEM shared secret; a future CRQC that breaks X25519 does not by itself recover them, assuming
  ML-KEM-768 is secure and the hybrid secret is used as in the TLS 1.3 key schedule (the setting analysed for
  concatenation combiners in RFC 9954, formerly draft-ietf-tls-hybrid-design; verified, see docs/RESEARCH.md).
- **Authentication is classical only.** Ed25519 is not post-quantum. An attacker with a CRQC *at handshake time*
  can impersonate the server. This is the same position as current hybrid TLS deployments.
- `X25519` alone provides no post-quantum confidentiality. `MLKEM768` alone provides no classical fallback if
  ML-KEM is broken.

## Known limitations / open risks
1. Formal analysis is symbolic and covers the specification only (formal/), not the Rust code; no HelloRetryRequest,
   no long-term key compromise.
2. No identity hiding; server key visible on the wire (by design, section 9 of the spec).
3. No client authentication.
4. No forward-secret resumption or key update; long sessions use one key per direction (sequence limit 2^64).
5. Zeroization: shared secrets, handshake/application traffic secrets and Finished keys are held in
   zeroize-on-drop containers (`zeroize` crate). Not covered: the AEAD key schedule inside `chacha20poly1305`,
   the transient `Key` copy passed to it, and compiler-introduced copies. Memory-disclosure attackers remain out of scope.
6. DoS: a single ClientHello forces the server to do an ML-KEM encapsulation plus X25519 and an Ed25519 signature
   (~0.6 ms measured, see results/). There is no cookie/stateless retry mechanism.
7. Fuzzing so far is a 60-second smoke run without a seed corpus (coverage 405 edges). Not a meaningful
   fuzzing campaign yet.
8. Side channels: no timing measurement (dudect/ctgrind) has been done. Source review (2026-11-22) of every
   secret-dependent comparison:
   - Finished MAC: `hmac`/`digest` `verify_slice` uses `ct_eq` (digest 0.11 `mac.rs`).
   - Record tags: `chacha20poly1305` 0.11 compares tags with `subtle` (`cipher.rs`).
   - X25519 contributory check: `was_contributory` -> `is_identity` -> `ct_eq` (curve25519-dalek 5.0 `traits.rs`).
   - ML-KEM implicit rejection: `ct_select` on a `ct_eq` of the re-encrypted ciphertext
     (ml-kem 0.3.4 `decapsulation_key.rs`).
   - QHandshake's own code branches only on public values (lengths, group codes, message types). A tampered
     ML-KEM ciphertext fails at the signature/Finished check, so there is no separate decapsulation-failure signal.
   Not verified: that the compiled binaries are constant-time on this CPU, and that the scalar-multiplication
   and polynomial arithmetic inside the crates are (their authors claim this; we did not test it).
9. The dependency crates (`ml-kem` 0.3.4 etc.) are themselves pre-1.0 / recently released; their audit status
   has not been reviewed here.

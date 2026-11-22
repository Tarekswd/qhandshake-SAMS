# QHandshake v1 - Protocol Specification (experimental)

Status: research prototype, version `0x7101`. Not TLS. Not interoperable with TLS. Not reviewed.

QHandshake is a deliberately small, TLS 1.3-shaped (RFC 8446 / RFC 9846) 1-RTT key exchange used as a
controlled testbed for hybrid post-quantum key establishment. Everything that is not needed to study
key establishment (certificates, PSK, 0-RTT, HelloRetryRequest, cipher-suite negotiation, encrypted
handshake messages) is intentionally absent, so that each measured byte and microsecond is attributable.

## 1. Message flow

```text
Client                                                    Server
------                                                    ------
ClientHello {version, random, groups[], key_shares[]} -->
                                                          select group (server preference)
                                     <-- ServerHello {version, random, group, key_share}
                                     <-- ServerVerify {Ed25519 signature}
                                     <-- Finished {server verify_data}
check group, decapsulate/DH, verify sig, verify Finished
Finished {client verify_data}                         -->
[AppData]  <====== ChaCha20-Poly1305, per-direction keys ======>  [AppData]
```

## 2. Framing

All messages: `type:u8 | length:u24 | body`. Maximum body: 65536 bytes (DoS bound).
Vectors inside bodies: `length:u16 | bytes`. Decoding is strict: unknown type, truncation,
trailing bytes, duplicate key shares, empty group list, 0 or more than 4 key shares are errors.

| type | message      | body |
|------|--------------|------|
| 1    | ClientHello  | version:u16, random[32], groups<u16 list>, share_count:u8, {group:u16, share<bytes>}* |
| 2    | ServerHello  | version:u16, random[32], group:u16, share<bytes> |
| 15   | ServerVerify | signature[64] (Ed25519) |
| 20   | Finished     | verify_data[32] |
| 21   | Alert        | code:u8 (sent before closing on any error; codes borrowed from RFC 8446 s.6) |
| 23   | AppData      | AEAD ciphertext (transport layer only) |

## 3. Groups

Codepoints are the IANA TLS Supported Groups values, reused so packet captures are self-describing.

| name           | code   | client share                    | server share                   | shared secret |
|----------------|--------|---------------------------------|--------------------------------|---------------|
| X25519         | 0x001D | x25519 pub (32)                 | x25519 pub (32)                | 32 B |
| MLKEM768       | 0x0201 | ML-KEM-768 ek (1184)            | ML-KEM-768 ct (1088)           | 32 B |
| X25519MLKEM768 | 0x11EC | ek (1184) \|\| x25519 pub (32)  | ct (1088) \|\| x25519 pub (32) | mlkem_ss \|\| x25519_ss (64 B) |

The hybrid layout and secret order follow RFC 10024 (draft-ietf-tls-ecdhe-mlkem-05).

Validation (each failure aborts with `illegal_parameter`):
- Exact share lengths per group.
- X25519: the shared secret must be contributory (non-zero), RFC 7748 s.6.1.
- ML-KEM-768: the encapsulation key must pass the FIPS 203 input check (performed by `ml-kem`'s `TryKeyInit`;
  test `invalid_mlkem_encapsulation_key_rejected` demonstrates rejection of out-of-range coefficients).
- A ciphertext that decapsulates under implicit rejection yields a pseudorandom secret; the handshake then
  fails at signature/Finished verification.

## 4. Negotiation

- The client sends a key share for **every** offered group (no HelloRetryRequest). Cost: each extra share
  adds bytes and a key generation; this is a measured trade-off, not an oversight.
- A key share for a group not listed in `groups` is `illegal_parameter`.
- The server picks the first group in **its own** preference list for which the client sent a share.
  No match: `handshake_failure`.
- The client checks that the selected group was offered (`illegal_parameter` otherwise) and, when its
  `require_pq` policy is set, that it contains ML-KEM (`handshake_failure` otherwise).
- Downgrade resistance comes from transcript authentication (section 6), not from negotiation rules.

## 5. Key schedule

Structure of RFC 8446 s.7.1 with SHA-256, but the HKDF label prefix is `"qh01 "` instead of `"tls13 "`
so that no QHandshake key can ever equal a TLS 1.3 key.

```text
HkdfLabel     = length:u16 | len:u8 | "qh01 " + label | len:u8 | context
Expand-Label(S, label, ctx, L) = HKDF-Expand(S, HkdfLabel, L)
Derive-Secret(S, label, TH)    = Expand-Label(S, label, TH, 32)

early   = HKDF-Extract(salt=0^32, ikm=0^32)
hs      = HKDF-Extract(salt=Derive-Secret(early, "derived", H("")), ikm=shared_secret)
c_hs    = Derive-Secret(hs, "c hs traffic", H(CH || SH))
s_hs    = Derive-Secret(hs, "s hs traffic", H(CH || SH))
master  = HKDF-Extract(salt=Derive-Secret(hs, "derived", H("")), ikm=0^32)
c_ap    = Derive-Secret(master, "c ap traffic", H(CH .. server Finished))
s_ap    = Derive-Secret(master, "s ap traffic", H(CH .. server Finished))
finished_key(S) = Expand-Label(S, "finished", "", 32)
```

`H` is SHA-256 over the exact encoded bytes of the messages (including 4-byte headers).
Known-answer vectors: `tests/kat.rs`, independently generated by `tools/kat.py` (stdlib Python).

## 6. Authentication

- Server identity: a raw Ed25519 public key pinned by the client (cf. RFC 7250). No PKI.
- `ServerVerify.signature = Ed25519.Sign(sk, 0x20*64 || "QHandshake v1, server ServerVerify" || 0x00 || H(CH || SH))`,
  verified with `verify_strict`.
- Server `Finished = HMAC-SHA256(finished_key(s_hs), H(CH .. ServerVerify))`.
- Client `Finished = HMAC-SHA256(finished_key(c_hs), H(CH .. server Finished))`, verified in constant time.
- The client is not authenticated (as in default TLS server-only authentication).

## 7. Application data

ChaCha20-Poly1305. Per direction: `key = Expand-Label(secret, "key", "", 32)`,
`iv = Expand-Label(secret, "iv", "", 12)`, `nonce = iv XOR (0^4 || seq:u64)`, seq starts at 0 and never wraps.
Records must be processed in order; a replayed, reordered or modified record fails authentication and
desynchronises the receive sequence, so any record failure is effectively fatal.

## 8. State machines

```text
Client: WaitServerHello -> WaitServerVerify -> WaitServerFinished -> Connected
Server: WaitClientHello -> WaitClientFinished -> Connected
Any error (decode, unexpected message, validation, crypto) -> Failed (terminal; later input -> Poisoned)
```

On failure, the ephemeral private keys and handshake secrets held by the state machine are dropped.

## 9. Differences from TLS 1.3 (deliberate)

| TLS 1.3 | QHandshake v1 | Consequence |
|---|---|---|
| EncryptedExtensions/Certificate/CertificateVerify encrypted under handshake keys | ServerVerify/Finished sent in clear | No server identity hiding |
| X.509 certificates | pinned raw Ed25519 key | No PKI, no revocation |
| HelloRetryRequest | absent | Client must send all shares up front |
| Cipher-suite negotiation | fixed SHA-256 / ChaCha20-Poly1305 | Smaller attack surface |
| PSK, 0-RTT, resumption, KeyUpdate, client auth | absent | Out of scope |
| "tls13 " labels | "qh01 " labels | Domain separation from TLS |

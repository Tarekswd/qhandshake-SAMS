# QHandshake

An experimental, TLS 1.3-modelled, server-authenticated **hybrid X25519 + ML-KEM-768** handshake, built as a
measurable testbed for post-quantum key establishment.

> **Research prototype.** Not TLS, not interoperable with TLS, not independently reviewed, not formally verified.
> Do not use it to protect real data.

## What it is / is not
- **Is:** a sans-IO client/server state machine, strict wire codec, TLS 1.3-structured key schedule, AEAD record
  layer, TCP transport, CLI, benchmarks, and adversarial tests. All cryptography comes from RustCrypto/dalek crates.
- **Is not:** a TLS extension, a TLS implementation, or a new cryptographic construction. The hybrid key exchange
  is the RFC 10024 `X25519MLKEM768` layout. See [docs/RESEARCH.md](docs/RESEARCH.md) for the honest novelty statement.

Documents: [spec/PROTOCOL.md](spec/PROTOCOL.md) (wire format, state machines, key schedule) |
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | [docs/RESEARCH.md](docs/RESEARCH.md) |
[docs/PAPER_DRAFT.md](docs/PAPER_DRAFT.md) | [docs/DEVELOPMENT_LOG.md](docs/DEVELOPMENT_LOG.md)

## Build and test
Requires Rust >= 1.89 on Linux (developed under WSL2 Ubuntu 24.04; native Windows needs the MSVC build tools).

```bash
cargo test --release           # 24 tests: e2e, MITM/downgrade, malformed input, KAT, property tests, TCP
cargo clippy --all-targets -- -D warnings
python3 tools/kat.py           # independent Python key schedule; exits 1 if tests/kat.rs vectors differ
```

## Run two nodes
```bash
bash examples/demo.sh          # keygen, server, 1 successful hybrid handshake, 2 expected failures with alerts
```
Manually:
```bash
PUB=$(cargo run -q --release --bin qh -- keygen server.key)
cargo run --release --bin qh -- server 127.0.0.1:4433 server.key x25519mlkem768,x25519 &
cargo run --release --bin qh -- client 127.0.0.1:4433 $PUB x25519mlkem768 "hello" --require-pq
```

## Benchmarks
```bash
bash benchmarks/run.sh 1000    # -> results/<timestamp>/{raw.csv, environment.txt, summary.md, handshake_latency.png}
```
Compares X25519-only, ML-KEM-768-only and the hybrid: per-primitive cost, in-process handshake CPU, and loopback TCP
time to first application byte. The plot requires matplotlib (`analyze.py` can be re-run on any machine against `raw.csv`).

## Fuzzing
```bash
cd fuzz && cargo +nightly fuzz run server_input --fuzz-dir . -- -max_total_time=60
```

## Status
Done: vertical slice (two TCP nodes, success and failure paths, alerts), 24 tests, mutation check of two security
checks, 60 s fuzz smoke run, n=1000 benchmark with raw data, zeroization of protocol secrets, CI (fmt, clippy, tests,
KAT cross-check, demo, 120 s fuzz smoke), paper draft with explicit TODO placeholders.
Not done: formal model, HelloRetryRequest, loss/RTT experiments, seeded fuzzing campaign, bare-metal benchmark.

## License
Apache-2.0 OR MIT, at your option ([LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT)).

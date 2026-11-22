//! Benchmark: X25519-only vs ML-KEM-768-only vs X25519MLKEM768 hybrid.
//!   qh-bench <iterations> <out.csv>
//! Writes one CSV row per measured handshake (raw data; analysis lives in benchmarks/analyze.py).
//! mode=inproc: sans-IO handshake in one thread, per-party CPU time measured with Instant.
//! mode=tcp:    loopback TCP, wall time from connect() to first echoed application byte.

use qhandshake::transport::{accept, connect, read_app, write_app};
use qhandshake::{Client, ClientConfig, Group, Server, ServerConfig};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

const GROUPS: [Group; 3] = [Group::X25519, Group::MlKem768, Group::X25519MlKem768];
const WARMUP: usize = 20;

fn inproc(g: Group, sk: &ed25519_dalek::SigningKey) -> (u128, u128, u128, usize, usize) {
    let t0 = Instant::now();
    let (mut c, ch) = Client::new(ClientConfig {
        offer: vec![g],
        server_key: sk.verifying_key(),
        require_pq: false,
    })
    .unwrap();
    let t_ch = t0.elapsed().as_nanos();
    let t1 = Instant::now();
    let mut s = Server::new(ServerConfig {
        accept: vec![g],
        signing_key: sk.clone(),
    })
    .unwrap();
    let flight = s.handle(&ch).unwrap();
    let t_server_a = t1.elapsed().as_nanos();
    let s2c: usize = flight.iter().map(Vec::len).sum();
    let t2 = Instant::now();
    let mut fin = vec![];
    for m in &flight {
        fin = c.handle(m).unwrap();
    }
    let t_client_b = t2.elapsed().as_nanos();
    let t3 = Instant::now();
    s.handle(&fin[0]).unwrap();
    let t_server_b = t3.elapsed().as_nanos();
    (
        t_ch + t_client_b,
        t_server_a + t_server_b,
        t_ch + t_server_a + t_client_b + t_server_b,
        ch.len() + fin[0].len(),
        s2c,
    )
}

type Op<'a> = Box<dyn FnMut() + 'a>;

/// Per-primitive cost, so handshake overhead can be attributed (mode=primitive, group=operation).
fn primitives(out: &mut std::fs::File, n: usize, sk: &ed25519_dalek::SigningKey) {
    use ed25519_dalek::Signer;
    use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
    let (dk, ek) = ml_kem::MlKem768::generate_keypair();
    let (ct, _) = ek.encapsulate();
    let peer = x25519_dalek::PublicKey::from(&x25519_dalek::EphemeralSecret::random());
    let sig = sk.sign(b"m");
    let mut ops: Vec<(&str, Op)> = vec![
        (
            "x25519_keygen",
            Box::new(|| {
                std::hint::black_box(x25519_dalek::PublicKey::from(
                    &x25519_dalek::EphemeralSecret::random(),
                ));
            }),
        ),
        (
            "x25519_dh",
            Box::new(move || {
                std::hint::black_box(x25519_dalek::EphemeralSecret::random().diffie_hellman(&peer));
            }),
        ),
        (
            "mlkem768_keygen",
            Box::new(|| {
                std::hint::black_box(ml_kem::MlKem768::generate_keypair());
            }),
        ),
        (
            "mlkem768_encaps",
            Box::new(move || {
                std::hint::black_box(ek.encapsulate());
            }),
        ),
        (
            "mlkem768_decaps",
            Box::new(move || {
                std::hint::black_box(dk.decapsulate(&ct));
            }),
        ),
        (
            "ed25519_sign",
            Box::new(|| {
                std::hint::black_box(sk.sign(b"m"));
            }),
        ),
        (
            "ed25519_verify",
            Box::new(move || {
                std::hint::black_box(sk.verifying_key().verify_strict(b"m", &sig)).unwrap();
            }),
        ),
        (
            "os_rng_32B",
            Box::new(|| {
                let mut b = [0u8; 32];
                getrandom::fill(&mut b).unwrap();
                std::hint::black_box(b);
            }),
        ),
    ];
    for (name, f) in ops.iter_mut() {
        for i in 0..WARMUP + n {
            let t = Instant::now();
            f();
            let ns = t.elapsed().as_nanos();
            if i >= WARMUP {
                writeln!(out, "primitive,{name},{},,,{ns},,", i - WARMUP).unwrap();
            }
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 3 {
        eprintln!("usage: qh-bench <iterations> <out.csv>");
        std::process::exit(2);
    }
    let n: usize = a[1].parse().expect("iterations must be an integer");
    let mut out = std::fs::File::create(&a[2]).expect("create output");
    writeln!(
        out,
        "mode,group,iter,client_ns,server_ns,total_ns,c2s_bytes,s2c_bytes"
    )
    .unwrap();
    let sk = qhandshake::generate_identity();
    primitives(&mut out, n, &sk);

    for g in GROUPS {
        for i in 0..WARMUP + n {
            let (c, s, t, c2s, s2c) = inproc(g, &sk);
            if i >= WARMUP {
                writeln!(out, "inproc,{g:?},{},{c},{s},{t},{c2s},{s2c}", i - WARMUP).unwrap();
            }
        }
    }

    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let ssk = sk.clone();
    std::thread::spawn(move || {
        for (conn, g) in l.incoming().zip(
            GROUPS
                .iter()
                .flat_map(|g| std::iter::repeat_n(*g, WARMUP + n)),
        ) {
            let mut s = conn.unwrap();
            let mut sv = accept(
                &mut s,
                ServerConfig {
                    accept: vec![g],
                    signing_key: ssk.clone(),
                },
            )
            .unwrap();
            let sess = sv.session().unwrap();
            let m = read_app(&mut s, sess).unwrap();
            write_app(&mut s, sess, &m).unwrap();
        }
    });
    for g in GROUPS {
        for i in 0..WARMUP + n {
            let t0 = Instant::now();
            let mut s = TcpStream::connect(addr).unwrap();
            let mut c = connect(
                &mut s,
                ClientConfig {
                    offer: vec![g],
                    server_key: sk.verifying_key(),
                    require_pq: false,
                },
            )
            .unwrap();
            let sess = c.session().unwrap();
            write_app(&mut s, sess, b"x").unwrap();
            read_app(&mut s, sess).unwrap();
            let t = t0.elapsed().as_nanos();
            if i >= WARMUP {
                writeln!(out, "tcp,{g:?},{},,,{t},,", i - WARMUP).unwrap();
            }
        }
    }
    eprintln!("wrote {}", a[2]);
}

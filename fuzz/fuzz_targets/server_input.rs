#![no_main]
//! Feeds arbitrary bytes to a fresh server as its first message, then (if accepted) a second message.
use libfuzzer_sys::fuzz_target;
use qhandshake::{Group, Server, ServerConfig};

fuzz_target!(|data: &[u8]| {
    let mut s = Server::new(ServerConfig {
        accept: vec![Group::X25519MlKem768, Group::MlKem768, Group::X25519],
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
    })
    .unwrap();
    let (a, b) = data.split_at(data.len() / 2);
    if s.handle(a).is_ok() {
        let _ = s.handle(b);
    }
});

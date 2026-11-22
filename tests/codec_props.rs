//! Property tests for the untrusted-input decoder.

use proptest::prelude::*;
use qhandshake::codec::{ClientHello, Message, VERSION};
use qhandshake::{ClientConfig, Group, Server, ServerConfig};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..3000)) {
        let _ = Message::decode(&bytes);
    }

    #[test]
    fn server_never_panics_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..3000)) {
        let mut s = Server::new(ServerConfig {
            accept: vec![Group::X25519MlKem768, Group::X25519],
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
        }).unwrap();
        let _ = s.handle(&bytes);
    }

    #[test]
    fn client_hello_roundtrips(random in any::<[u8; 32]>(),
                               groups in proptest::collection::vec(any::<u16>(), 1..8),
                               share in proptest::collection::vec(any::<u8>(), 0..1300)) {
        let m = Message::ClientHello(ClientHello { version: VERSION, random, groups: groups.clone(), shares: vec![(groups[0], share)] });
        prop_assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    }
}

#[test]
fn every_truncation_of_a_real_client_hello_is_rejected() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let (_, ch) = qhandshake::Client::new(ClientConfig {
        offer: vec![Group::X25519MlKem768, Group::X25519],
        server_key: sk.verifying_key(),
        require_pq: false,
    })
    .unwrap();
    for n in 0..ch.len() {
        assert!(
            Message::decode(&ch[..n]).is_err(),
            "prefix of {n} bytes accepted"
        );
    }
    let mut long = ch.clone();
    long.push(0);
    assert!(Message::decode(&long).is_err());
}

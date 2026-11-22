//! Positive and negative end-to-end tests of the sans-IO state machines, including an active
//! man-in-the-middle that rewrites messages in flight.

use qhandshake::codec::{ClientHello, Message, VERSION};
use qhandshake::{
    Client, ClientConfig, ClientState, Error, Group, Server, ServerConfig, ServerState,
};

use Group::*;

fn cfgs(offer: &[Group], accept: &[Group]) -> (ClientConfig, ServerConfig) {
    let sk = qhandshake::generate_identity();
    (
        ClientConfig {
            offer: offer.to_vec(),
            server_key: sk.verifying_key(),
            require_pq: false,
        },
        ServerConfig {
            accept: accept.to_vec(),
            signing_key: sk,
        },
    )
}

/// Runs a full handshake, applying `mitm` to every message (direction: true = client->server).
fn run(
    cc: ClientConfig,
    sc: ServerConfig,
    mut mitm: impl FnMut(bool, Vec<u8>) -> Vec<u8>,
) -> (Client, Server, Result<(), Error>) {
    let (mut c, ch) = Client::new(cc).unwrap();
    let mut s = Server::new(sc).unwrap();
    let r = (|| {
        let flight = s.handle(&mitm(true, ch))?;
        let mut out = vec![];
        for m in flight {
            out = c.handle(&mitm(false, m))?;
        }
        for m in out {
            s.handle(&mitm(true, m))?;
        }
        Ok(())
    })();
    (c, s, r)
}

fn decode_ch(raw: &[u8]) -> ClientHello {
    match Message::decode(raw).unwrap() {
        Message::ClientHello(ch) => ch,
        m => panic!("expected ClientHello, got {m:?}"),
    }
}

#[test]
fn all_groups_complete_and_exchange_data() {
    for g in [X25519, MlKem768, X25519MlKem768] {
        let (cc, sc) = cfgs(&[g], &[g]);
        let (mut c, mut s, r) = run(cc, sc, |_, m| m);
        r.unwrap();
        assert_eq!(c.state(), ClientState::Connected);
        assert_eq!(s.state(), ServerState::Connected);
        assert_eq!((c.group(), s.group()), (Some(g), Some(g)));
        let ct = c.session().unwrap().seal(b"ping").unwrap();
        assert_eq!(s.session().unwrap().open(&ct).unwrap(), b"ping");
        let ct = s.session().unwrap().seal(b"pong").unwrap();
        assert_eq!(c.session().unwrap().open(&ct).unwrap(), b"pong");
    }
}

#[test]
fn server_preference_selects_hybrid() {
    let (cc, sc) = cfgs(&[X25519, X25519MlKem768], &[X25519MlKem768, X25519]);
    let (c, _, r) = run(cc, sc, |_, m| m);
    r.unwrap();
    assert_eq!(c.group(), Some(X25519MlKem768));
}

#[test]
fn downgrade_by_stripping_hybrid_share_is_detected() {
    let (cc, sc) = cfgs(&[X25519MlKem768, X25519], &[X25519MlKem768, X25519]);
    let (c, s, r) = run(cc, sc, |to_server, m| {
        if to_server && m[0] == 1 {
            let mut ch = decode_ch(&m);
            ch.groups.retain(|g| *g == X25519.code());
            ch.shares.retain(|(g, _)| *g == X25519.code());
            Message::ClientHello(ch).encode()
        } else {
            m
        }
    });
    // Server was fooled into X25519, but its signature covers the modified ClientHello.
    assert_eq!(s.group(), Some(X25519));
    assert_eq!(r, Err(Error::BadSignature));
    assert_eq!(c.state(), ClientState::Failed);
}

#[test]
fn require_pq_rejects_classical_only_server() {
    let (mut cc, sc) = cfgs(&[X25519MlKem768, X25519], &[X25519]);
    cc.require_pq = true;
    let (_, _, r) = run(cc, sc, |_, m| m);
    assert!(matches!(r, Err(Error::HandshakeFailure(_))));
}

#[test]
fn require_pq_without_pq_offer_is_a_config_error() {
    let (mut cc, _) = cfgs(&[X25519], &[X25519]);
    cc.require_pq = true;
    assert!(matches!(Client::new(cc), Err(Error::Config(_))));
}

#[test]
fn wrong_pinned_key_fails() {
    let (mut cc, sc) = cfgs(&[X25519MlKem768], &[X25519MlKem768]);
    cc.server_key = qhandshake::generate_identity().verifying_key();
    let (_, _, r) = run(cc, sc, |_, m| m);
    assert_eq!(r, Err(Error::BadSignature));
}

#[test]
fn tampered_server_hello_share_fails() {
    for g in [X25519, MlKem768, X25519MlKem768] {
        let (cc, sc) = cfgs(&[g], &[g]);
        let (_, _, r) = run(cc, sc, |to_server, mut m| {
            if !to_server && m[0] == 2 {
                *m.last_mut().unwrap() ^= 1;
            }
            m
        });
        assert!(r.is_err(), "{g:?}: tampered ServerHello accepted");
    }
}

#[test]
fn tampered_server_finished_fails() {
    let (cc, sc) = cfgs(&[X25519MlKem768], &[X25519MlKem768]);
    let (_, _, r) = run(cc, sc, |to_server, mut m| {
        if !to_server && m[0] == 20 {
            m[10] ^= 0x80;
        }
        m
    });
    assert!(matches!(r, Err(Error::DecryptError(_))));
}

#[test]
fn server_selecting_unoffered_group_is_rejected() {
    // Client A offers X25519 only; a ServerHello from a hybrid handshake is delivered to it.
    let (cc_a, _) = cfgs(&[X25519], &[X25519]);
    let (cc_b, sc_b) = cfgs(&[X25519MlKem768], &[X25519MlKem768]);
    let (mut a, _) = Client::new(cc_a).unwrap();
    let (_, ch_b) = Client::new(cc_b).unwrap();
    let sh = Server::new(sc_b).unwrap().handle(&ch_b).unwrap().remove(0);
    assert!(matches!(a.handle(&sh), Err(Error::IllegalParameter(_))));
}

#[test]
fn out_of_order_message_poisons_state_machine() {
    let (cc, sc) = cfgs(&[X25519], &[X25519]);
    let (mut c, _) = Client::new(cc).unwrap();
    let fin = Message::Finished([0; 32]).encode();
    assert!(matches!(c.handle(&fin), Err(Error::UnexpectedMessage(_))));
    assert_eq!(c.state(), ClientState::Failed);
    assert_eq!(c.handle(&fin), Err(Error::Poisoned));

    let mut s = Server::new(sc).unwrap();
    assert!(matches!(s.handle(&fin), Err(Error::UnexpectedMessage(_))));
    assert_eq!(s.handle(&fin), Err(Error::Poisoned));
}

#[test]
fn replayed_client_flight_is_rejected_by_fresh_server() {
    let (cc, sc) = cfgs(&[X25519MlKem768], &[X25519MlKem768]);
    let sk = sc.signing_key.clone();
    let mut recorded = vec![];
    let (_, _, r) = run(cc, sc, |to_server, m| {
        if to_server {
            recorded.push(m.clone());
        }
        m
    });
    r.unwrap();
    let mut fresh = Server::new(ServerConfig {
        accept: vec![X25519MlKem768],
        signing_key: sk,
    })
    .unwrap();
    fresh.handle(&recorded[0]).unwrap(); // server answers with new random + new ephemeral
    assert!(matches!(
        fresh.handle(&recorded[1]),
        Err(Error::DecryptError(_))
    ));
}

fn ch_with_share(g: Group, share: Vec<u8>) -> Vec<u8> {
    Message::ClientHello(ClientHello {
        version: VERSION,
        random: [7; 32],
        groups: vec![g.code()],
        shares: vec![(g.code(), share)],
    })
    .encode()
}

fn server_for(g: Group) -> Server {
    Server::new(ServerConfig {
        accept: vec![g],
        signing_key: qhandshake::generate_identity(),
    })
    .unwrap()
}

#[test]
fn x25519_low_order_point_rejected() {
    for g in [X25519, X25519MlKem768] {
        let mut share = vec![];
        if g == X25519MlKem768 {
            let (_, ch) = Client::new(cfgs(&[g], &[g]).0).unwrap();
            share = decode_ch(&ch).shares[0].1[..1184].to_vec();
        }
        share.extend([0u8; 32]); // the identity point; X25519 output would be all-zero
        let r = server_for(g).handle(&ch_with_share(g, share));
        assert_eq!(
            r,
            Err(Error::IllegalParameter("x25519 low-order point")),
            "{g:?}"
        );
    }
}

#[test]
fn invalid_mlkem_encapsulation_key_rejected() {
    // 0xFF.. encodes coefficients 0xFFF >= q = 3329, failing the FIPS 203 modulus check.
    let r = server_for(MlKem768).handle(&ch_with_share(MlKem768, vec![0xFF; 1184]));
    assert_eq!(
        r,
        Err(Error::IllegalParameter("invalid ML-KEM encapsulation key"))
    );
}

#[test]
fn wrong_share_lengths_rejected() {
    for (g, len) in [(X25519, 31), (MlKem768, 1183), (X25519MlKem768, 1184 + 33)] {
        let r = server_for(g).handle(&ch_with_share(g, vec![1; len]));
        assert_eq!(r, Err(Error::IllegalParameter("key share length")), "{g:?}");
    }
}

#[test]
fn share_for_unlisted_group_rejected() {
    let (_, ch) = Client::new(cfgs(&[X25519], &[X25519]).0).unwrap();
    let mut ch = decode_ch(&ch);
    ch.groups = vec![MlKem768.code()];
    let r = server_for(X25519).handle(&Message::ClientHello(ch).encode());
    assert!(matches!(r, Err(Error::IllegalParameter(_))));
}

#[test]
fn version_mismatch_rejected() {
    let (_, ch) = Client::new(cfgs(&[X25519], &[X25519]).0).unwrap();
    let mut ch = decode_ch(&ch);
    ch.version = 0x0304;
    assert_eq!(
        server_for(X25519).handle(&Message::ClientHello(ch).encode()),
        Err(Error::ProtocolVersion)
    );
}

#[test]
fn record_replay_and_tamper_rejected() {
    let (cc, sc) = cfgs(&[X25519MlKem768], &[X25519MlKem768]);
    let (mut c, mut s, r) = run(cc, sc, |_, m| m);
    r.unwrap();
    let ct1 = c.session().unwrap().seal(b"one").unwrap();
    let mut ct2 = c.session().unwrap().seal(b"two").unwrap();
    assert_eq!(s.session().unwrap().open(&ct1).unwrap(), b"one");
    assert!(
        s.session().unwrap().open(&ct1).is_err(),
        "replayed record accepted"
    );
    ct2[0] ^= 1;
    assert!(
        s.session().unwrap().open(&ct2).is_err(),
        "tampered record accepted"
    );
}

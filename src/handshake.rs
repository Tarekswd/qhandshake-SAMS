//! Client and server handshake state machines (sans-IO: bytes in, bytes out).
//!
//! ```text
//! Client                                         Server
//! ClientHello{random, groups, key_shares} -->
//!                                       <-- ServerHello{random, group, key_share}
//!                                       <-- ServerVerify{Ed25519 sig over H(CH||SH)}
//!                                       <-- Finished{HMAC(s_hs, H(CH..SV))}
//! Finished{HMAC(c_hs, H(CH..SF))}       -->
//! [application data, ChaCha20-Poly1305 under c/s ap traffic secrets]
//! ```
//! Any error moves the machine to `Failed`; every later call returns `Error::Poisoned`.

use crate::codec::{ClientHello, Message, ServerHello, VERSION};
use crate::crypto::{self, ClientPrivate, Group, HandshakeSecrets, Secret};
use crate::record::Session;
use crate::{ClientConfig, Error, ServerConfig};
use ed25519_dalek::Signer;
use zeroize::Zeroizing;

fn random() -> [u8; 32] {
    let mut r = [0u8; 32];
    getrandom::fill(&mut r).expect("OS RNG unavailable");
    r
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    WaitServerHello,
    WaitServerVerify,
    WaitServerFinished,
    Connected,
    Failed,
}

pub struct Client {
    cfg: ClientConfig,
    state: ClientState,
    transcript: Vec<u8>,
    privs: Vec<ClientPrivate>,
    group: Option<Group>,
    hs: Option<HandshakeSecrets>,
    th_hello: Secret,
    session: Option<Session>,
}

impl Client {
    /// Validates the config and returns the client plus its encoded ClientHello.
    pub fn new(cfg: ClientConfig) -> Result<(Self, Vec<u8>), Error> {
        cfg.validate()?;
        let mut privs = Vec::new();
        let mut shares = Vec::new();
        for &g in &cfg.offer {
            let (p, s) = crypto::client_share(g);
            privs.push(p);
            shares.push((g.code(), s));
        }
        let ch = Message::ClientHello(ClientHello {
            version: VERSION,
            random: random(),
            groups: cfg.offer.iter().map(|g| g.code()).collect(),
            shares,
        })
        .encode();
        let c = Client {
            cfg,
            state: ClientState::WaitServerHello,
            transcript: ch.clone(),
            privs,
            group: None,
            hs: None,
            th_hello: [0; 32],
            session: None,
        };
        Ok((c, ch))
    }

    pub fn state(&self) -> ClientState {
        self.state
    }
    pub fn group(&self) -> Option<Group> {
        self.group
    }
    /// Available once `state() == Connected`.
    pub fn session(&mut self) -> Option<&mut Session> {
        self.session.as_mut()
    }

    pub fn handle(&mut self, raw: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if self.state == ClientState::Failed {
            return Err(Error::Poisoned);
        }
        let r = self.step(raw);
        if r.is_err() {
            self.state = ClientState::Failed;
            self.privs.clear();
            self.hs = None;
        }
        r
    }

    fn step(&mut self, raw: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let msg = Message::decode(raw)?;
        match (self.state, msg) {
            (ClientState::WaitServerHello, Message::ServerHello(sh)) => {
                if sh.version != VERSION {
                    return Err(Error::ProtocolVersion);
                }
                let g = Group::from_code(sh.group)
                    .filter(|g| self.cfg.offer.contains(g))
                    .ok_or(Error::IllegalParameter(
                        "server selected a group the client did not offer",
                    ))?;
                if self.cfg.require_pq && !g.is_post_quantum() {
                    return Err(Error::HandshakeFailure(
                        "policy requires a post-quantum group",
                    ));
                }
                let idx = self
                    .cfg
                    .offer
                    .iter()
                    .position(|x| *x == g)
                    .expect("checked above");
                let p = self.privs.swap_remove(idx);
                self.privs.clear(); // drop unused ephemeral keys immediately
                let ss = crypto::client_finish(p, &sh.share)?;
                self.transcript.extend(raw);
                self.th_hello = crypto::hash(&self.transcript);
                self.hs = Some(crypto::handshake_secrets(&ss, &self.th_hello));
                self.group = Some(g);
                self.state = ClientState::WaitServerVerify;
                Ok(vec![])
            }
            (ClientState::WaitServerVerify, Message::ServerVerify(sig)) => {
                let sig = ed25519_dalek::Signature::from_bytes(&sig);
                self.cfg
                    .server_key
                    .verify_strict(&crypto::server_verify_content(&self.th_hello), &sig)
                    .map_err(|_| Error::BadSignature)?;
                self.transcript.extend(raw);
                self.state = ClientState::WaitServerFinished;
                Ok(vec![])
            }
            (ClientState::WaitServerFinished, Message::Finished(mac)) => {
                let hs = self.hs.as_ref().expect("set in WaitServerHello");
                crypto::verify_finished(&hs.server_hs, &crypto::hash(&self.transcript), &mac)?;
                self.transcript.extend(raw);
                let th = crypto::hash(&self.transcript);
                let (c_ap, s_ap) = crypto::application_secrets(&hs.handshake_secret, &th);
                let fin = Message::Finished(crypto::finished_mac(&hs.client_hs, &th)).encode();
                self.transcript.extend(&fin);
                self.session = Some(Session::new(&c_ap, &s_ap));
                self.hs = None;
                self.state = ClientState::Connected;
                Ok(vec![fin])
            }
            _ => Err(Error::UnexpectedMessage(
                "client received message out of order",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerState {
    WaitClientHello,
    WaitClientFinished,
    Connected,
    Failed,
}

pub struct Server {
    cfg: ServerConfig,
    state: ServerState,
    transcript: Vec<u8>,
    group: Option<Group>,
    client_hs: Zeroizing<Secret>,
    app: Option<(Zeroizing<Secret>, Zeroizing<Secret>)>,
    session: Option<Session>,
}

impl Server {
    pub fn new(cfg: ServerConfig) -> Result<Self, Error> {
        cfg.validate()?;
        Ok(Server {
            cfg,
            state: ServerState::WaitClientHello,
            transcript: Vec::new(),
            group: None,
            client_hs: Zeroizing::new([0; 32]),
            app: None,
            session: None,
        })
    }

    pub fn state(&self) -> ServerState {
        self.state
    }
    pub fn group(&self) -> Option<Group> {
        self.group
    }
    pub fn session(&mut self) -> Option<&mut Session> {
        self.session.as_mut()
    }

    pub fn handle(&mut self, raw: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if self.state == ServerState::Failed {
            return Err(Error::Poisoned);
        }
        let r = self.step(raw);
        if r.is_err() {
            self.state = ServerState::Failed;
            self.app = None;
        }
        r
    }

    fn step(&mut self, raw: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let msg = Message::decode(raw)?;
        match (self.state, msg) {
            (ServerState::WaitClientHello, Message::ClientHello(ch)) => {
                if ch.version != VERSION {
                    return Err(Error::ProtocolVersion);
                }
                if ch.shares.iter().any(|(g, _)| !ch.groups.contains(g)) {
                    return Err(Error::IllegalParameter(
                        "key share for a group not in the offer list",
                    ));
                }
                // Server preference wins, as in RFC 8446 section 4.2.7; no HelloRetryRequest support.
                let g = self
                    .cfg
                    .accept
                    .iter()
                    .copied()
                    .find(|g| ch.shares.iter().any(|(c, _)| *c == g.code()))
                    .ok_or(Error::HandshakeFailure(
                        "no mutually supported group with a key share",
                    ))?;
                let client_share = &ch
                    .shares
                    .iter()
                    .find(|(c, _)| *c == g.code())
                    .expect("found above")
                    .1;
                let (share, ss) = crypto::server_respond(g, client_share)?;
                self.transcript.extend(raw);
                let sh = Message::ServerHello(ServerHello {
                    version: VERSION,
                    random: random(),
                    group: g.code(),
                    share,
                })
                .encode();
                self.transcript.extend(&sh);
                let th_hello = crypto::hash(&self.transcript);
                let hs = crypto::handshake_secrets(&ss, &th_hello);
                let sig = self
                    .cfg
                    .signing_key
                    .sign(&crypto::server_verify_content(&th_hello));
                let sv = Message::ServerVerify(sig.to_bytes()).encode();
                self.transcript.extend(&sv);
                let sf = Message::Finished(crypto::finished_mac(
                    &hs.server_hs,
                    &crypto::hash(&self.transcript),
                ))
                .encode();
                self.transcript.extend(&sf);
                self.app = Some(crypto::application_secrets(
                    &hs.handshake_secret,
                    &crypto::hash(&self.transcript),
                ));
                *self.client_hs = hs.client_hs;
                self.group = Some(g);
                self.state = ServerState::WaitClientFinished;
                Ok(vec![sh, sv, sf])
            }
            (ServerState::WaitClientFinished, Message::Finished(mac)) => {
                crypto::verify_finished(&self.client_hs, &crypto::hash(&self.transcript), &mac)?;
                self.transcript.extend(raw);
                let (c_ap, s_ap) = self.app.take().expect("set in WaitClientHello");
                self.session = Some(Session::new(&s_ap, &c_ap));
                self.state = ServerState::Connected;
                Ok(vec![])
            }
            _ => Err(Error::UnexpectedMessage(
                "server received message out of order",
            )),
        }
    }
}

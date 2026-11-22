//! Key exchange groups and the key schedule. No primitive is implemented here: X25519, ML-KEM-768,
//! HKDF, HMAC and SHA-256 all come from the RustCrypto / dalek crates.
//!
//! Hybrid construction: exactly the X25519MLKEM768 layout of RFC 10024 / draft-ietf-tls-ecdhe-mlkem
//! (client share = ek || x25519_pub, server share = ct || x25519_pub, ss = mlkem_ss || x25519_ss).
//! The concatenated secret is only ever used as HKDF-Extract IKM inside a TLS 1.3-style key schedule
//! whose later derivations bind the full transcript (which contains both public shares and the
//! ciphertext); that is the setting analysed by draft-ietf-tls-hybrid-design. It is not claimed to be
//! a standalone secure KEM combiner (for that, see X-Wing).

use crate::Error;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit};
use ml_kem::{MlKem768, ml_kem_768};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub type Secret = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    X25519,
    MlKem768,
    X25519MlKem768,
}

impl Group {
    /// IANA TLS Supported Groups codepoints (29, 513, 4588). Reused so captures are self-describing;
    /// this protocol is NOT TLS and does not claim interoperability.
    pub const fn code(self) -> u16 {
        match self {
            Group::X25519 => 0x001D,
            Group::MlKem768 => 0x0201,
            Group::X25519MlKem768 => 0x11EC,
        }
    }
    pub fn from_code(c: u16) -> Option<Self> {
        [Group::X25519, Group::MlKem768, Group::X25519MlKem768]
            .into_iter()
            .find(|g| g.code() == c)
    }
    pub fn is_post_quantum(self) -> bool {
        self != Group::X25519
    }
}

pub(crate) struct ClientPrivate {
    group: Group,
    x: Option<EphemeralSecret>,
    k: Option<ml_kem_768::DecapsulationKey>,
}

const MLKEM_EK: usize = 1184;
const MLKEM_CT: usize = 1088;

pub(crate) fn client_share(group: Group) -> (ClientPrivate, Vec<u8>) {
    let mut share = Vec::new();
    let mut p = ClientPrivate {
        group,
        x: None,
        k: None,
    };
    if group.is_post_quantum() {
        let (dk, ek) = MlKem768::generate_keypair();
        share.extend_from_slice(&ek.to_bytes());
        p.k = Some(dk);
    }
    if group != Group::MlKem768 {
        let sk = EphemeralSecret::random();
        share.extend_from_slice(PublicKey::from(&sk).as_bytes());
        p.x = Some(sk);
    }
    (p, share)
}

/// Shared secrets live in buffers that are wiped on drop. Capacity is reserved up front so that
/// appending the X25519 part never reallocates (a reallocation would leave an unwiped copy).
pub(crate) type SharedSecret = Zeroizing<Vec<u8>>;

fn new_shared(first: &[u8]) -> SharedSecret {
    let mut v = Zeroizing::new(Vec::with_capacity(64));
    v.extend_from_slice(first);
    v
}

fn x25519(sk: EphemeralSecret, peer: &[u8]) -> Result<Zeroizing<Secret>, Error> {
    let peer: [u8; 32] = peer
        .try_into()
        .map_err(|_| Error::IllegalParameter("x25519 share length"))?;
    let ss = sk.diffie_hellman(&PublicKey::from(peer));
    // RFC 7748 section 6.1 / RFC 8446 section 7.4.2: reject the all-zero output (low-order peer point).
    if !ss.was_contributory() {
        return Err(Error::IllegalParameter("x25519 low-order point"));
    }
    Ok(Zeroizing::new(ss.to_bytes()))
}

fn split(share: &[u8], first: usize, total: usize) -> Result<(&[u8], &[u8]), Error> {
    if share.len() != total {
        return Err(Error::IllegalParameter("key share length"));
    }
    Ok(share.split_at(first))
}

/// Server side: consume the client's share, produce (server share, shared secret).
pub(crate) fn server_respond(
    group: Group,
    client: &[u8],
) -> Result<(Vec<u8>, SharedSecret), Error> {
    let encap = |ek: &[u8]| -> Result<(Vec<u8>, SharedSecret), Error> {
        // TryKeyInit performs the FIPS 203 encapsulation-key check; a failing key aborts the handshake.
        let ek = ml_kem_768::EncapsulationKey::new_from_slice(ek)
            .map_err(|_| Error::IllegalParameter("invalid ML-KEM encapsulation key"))?;
        let (ct, mut ss) = ek.encapsulate();
        let out = new_shared(&ss);
        ss.zeroize();
        Ok((ct.to_vec(), out))
    };
    let xdh = |peer: &[u8]| -> Result<(Vec<u8>, Zeroizing<Secret>), Error> {
        let sk = EphemeralSecret::random();
        let pk = PublicKey::from(&sk).to_bytes().to_vec();
        Ok((pk, x25519(sk, peer)?))
    };
    match group {
        Group::X25519 => {
            let (pk, ss) = xdh(split(client, 32, 32)?.0)?;
            Ok((pk, new_shared(&*ss)))
        }
        Group::MlKem768 => encap(split(client, MLKEM_EK, MLKEM_EK)?.0),
        Group::X25519MlKem768 => {
            let (ek, xp) = split(client, MLKEM_EK, MLKEM_EK + 32)?;
            let (mut share, mut ss) = encap(ek)?;
            let (pk, xss) = xdh(xp)?;
            share.extend(pk);
            ss.extend_from_slice(&*xss); // order: ML-KEM ss || X25519 ss (RFC 10024)
            Ok((share, ss))
        }
    }
}

/// Client side: combine own private state with the server's share.
pub(crate) fn client_finish(p: ClientPrivate, server: &[u8]) -> Result<SharedSecret, Error> {
    let decap = |dk: &ml_kem_768::DecapsulationKey, ct: &[u8]| -> Result<SharedSecret, Error> {
        // ML-KEM uses implicit rejection: a tampered ciphertext yields a pseudorandom secret, which
        // then fails the transcript/Finished checks rather than here.
        let mut ss = dk
            .decapsulate_slice(ct)
            .map_err(|_| Error::IllegalParameter("ML-KEM ciphertext length"))?;
        let out = new_shared(&ss);
        ss.zeroize();
        Ok(out)
    };
    match p.group {
        Group::X25519 => Ok(new_shared(&*x25519(
            p.x.expect("x25519 key"),
            split(server, 32, 32)?.0,
        )?)),
        Group::MlKem768 => decap(
            p.k.as_ref().expect("mlkem key"),
            split(server, MLKEM_CT, MLKEM_CT)?.0,
        ),
        Group::X25519MlKem768 => {
            let (ct, xp) = split(server, MLKEM_CT, MLKEM_CT + 32)?;
            let mut ss = decap(p.k.as_ref().expect("mlkem key"), ct)?;
            ss.extend_from_slice(&*x25519(p.x.expect("x25519 key"), xp)?);
            Ok(ss)
        }
    }
}

// ---------------- Key schedule (RFC 8446 section 7.1 structure, own label prefix) ----------------

/// Label prefix. Deliberately not "tls13 " so keys can never collide with a real TLS 1.3 session.
const LABEL_PREFIX: &[u8] = b"qh01 ";

pub fn hash(data: &[u8]) -> Secret {
    Sha256::digest(data).into()
}

pub fn expand_label(secret: &Secret, label: &str, context: &[u8], out: &mut [u8]) {
    let mut info = Vec::with_capacity(4 + LABEL_PREFIX.len() + label.len() + context.len());
    info.extend((out.len() as u16).to_be_bytes());
    info.push((LABEL_PREFIX.len() + label.len()) as u8);
    info.extend(LABEL_PREFIX);
    info.extend(label.as_bytes());
    info.push(context.len() as u8);
    info.extend(context);
    Hkdf::<Sha256>::from_prk(secret)
        .expect("32-byte PRK")
        .expand(&info, out)
        .expect("valid length");
}

pub fn derive_secret(secret: &Secret, label: &str, transcript_hash: &Secret) -> Secret {
    let mut out = [0u8; 32];
    expand_label(secret, label, transcript_hash, &mut out);
    out
}

fn extract(salt: &Secret, ikm: &[u8]) -> Secret {
    Hkdf::<Sha256>::extract(Some(salt), ikm).0.into()
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HandshakeSecrets {
    pub handshake_secret: Secret,
    pub client_hs: Secret,
    pub server_hs: Secret,
}

/// `th_hello` = SHA-256(ClientHello || ServerHello).
pub fn handshake_secrets(shared: &[u8], th_hello: &Secret) -> HandshakeSecrets {
    let early = extract(&[0; 32], &[0; 32]);
    let derived = derive_secret(&early, "derived", &hash(b""));
    let hs = extract(&derived, shared);
    HandshakeSecrets {
        handshake_secret: hs,
        client_hs: derive_secret(&hs, "c hs traffic", th_hello),
        server_hs: derive_secret(&hs, "s hs traffic", th_hello),
    }
}

/// `th_server_fin` = transcript hash through the server Finished. Returns (client_app, server_app).
pub fn application_secrets(
    handshake_secret: &Secret,
    th_server_fin: &Secret,
) -> (Zeroizing<Secret>, Zeroizing<Secret>) {
    let derived = derive_secret(handshake_secret, "derived", &hash(b""));
    let master = Zeroizing::new(extract(&derived, &[0; 32]));
    (
        Zeroizing::new(derive_secret(&master, "c ap traffic", th_server_fin)),
        Zeroizing::new(derive_secret(&master, "s ap traffic", th_server_fin)),
    )
}

pub fn finished_mac(base: &Secret, th: &Secret) -> [u8; 32] {
    let mut key = Zeroizing::new([0u8; 32]);
    expand_label(base, "finished", b"", &mut *key);
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&*key).expect("any key length");
    m.update(th);
    m.finalize().into_bytes().into()
}

/// Constant-time Finished verification.
pub fn verify_finished(base: &Secret, th: &Secret, mac: &[u8; 32]) -> Result<(), Error> {
    let mut key = Zeroizing::new([0u8; 32]);
    expand_label(base, "finished", b"", &mut *key);
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&*key).expect("any key length");
    m.update(th);
    m.verify_slice(mac)
        .map_err(|_| Error::DecryptError("Finished MAC mismatch"))
}

/// Content signed by the server, structured as RFC 8446 section 4.4.3 with our own context string.
pub fn server_verify_content(th_hello: &Secret) -> Vec<u8> {
    let mut v = vec![0x20u8; 64];
    v.extend(b"QHandshake v1, server ServerVerify");
    v.push(0);
    v.extend(th_hello);
    v
}

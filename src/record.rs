//! Application-data protection: ChaCha20-Poly1305, per-direction key/IV from Expand-Label and
//! nonce = IV xor seq (RFC 8446 section 5.3). Records must arrive in order; a replayed or reordered
//! record fails authentication because its nonce no longer matches.

use crate::Error;
use crate::crypto::{Secret, expand_label};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

struct Direction {
    aead: ChaCha20Poly1305,
    iv: [u8; 12],
    seq: u64,
}

impl Direction {
    fn new(secret: &Secret) -> Self {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        let mut iv = [0u8; 12];
        expand_label(secret, "key", b"", &mut *key);
        expand_label(secret, "iv", b"", &mut iv);
        Direction {
            aead: ChaCha20Poly1305::new(&Key::from(*key)),
            iv,
            seq: 0,
        }
    }
    fn nonce(&mut self) -> Result<Nonce, Error> {
        let mut n = self.iv;
        for (a, b) in n[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *a ^= b;
        }
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(Error::DecryptError("sequence number exhausted"))?;
        Ok(Nonce::from(n))
    }
}

pub struct Session {
    send: Direction,
    recv: Direction,
}

impl Session {
    pub(crate) fn new(send: &Secret, recv: &Secret) -> Self {
        Session {
            send: Direction::new(send),
            recv: Direction::new(recv),
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let n = self.send.nonce()?;
        self.send
            .aead
            .encrypt(&n, plaintext)
            .map_err(|_| Error::DecryptError("encryption failed"))
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let n = self.recv.nonce()?;
        self.recv
            .aead
            .decrypt(&n, ciphertext)
            .map_err(|_| Error::DecryptError("record authentication failed"))
    }
}

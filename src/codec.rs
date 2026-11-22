//! Wire format. Every handshake message is `type:u8 | length:u24 | body` (same framing as
//! RFC 8446 section 4). Vectors inside bodies are `length:u16 | bytes`.
//! The decoder is the main untrusted-input surface: it must never panic (see proptest in tests/).

use crate::Error;

pub const VERSION: u16 = 0x7101; // experimental, deliberately not a TLS version number
pub const MAX_MESSAGE: usize = 1 << 16; // DoS bound; largest legit message (hybrid+ML-KEM+X25519 ClientHello) is ~2.5 KiB
const MAX_SHARES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    ClientHello = 1,
    ServerHello = 2,
    ServerVerify = 15, // analogue of CertificateVerify
    Finished = 20,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u16,
    pub random: [u8; 32],
    /// Client preference order, most preferred first.
    pub groups: Vec<u16>,
    pub shares: Vec<(u16, Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHello {
    pub version: u16,
    pub random: [u8; 32],
    pub group: u16,
    pub share: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    ServerVerify([u8; 64]),
    Finished([u8; 32]),
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        let t = match self {
            Message::ClientHello(ch) => {
                b.extend(ch.version.to_be_bytes());
                b.extend(ch.random);
                put_vec(
                    &mut b,
                    &ch.groups
                        .iter()
                        .flat_map(|g| g.to_be_bytes())
                        .collect::<Vec<_>>(),
                );
                b.push(ch.shares.len() as u8);
                for (g, s) in &ch.shares {
                    b.extend(g.to_be_bytes());
                    put_vec(&mut b, s);
                }
                MsgType::ClientHello
            }
            Message::ServerHello(sh) => {
                b.extend(sh.version.to_be_bytes());
                b.extend(sh.random);
                b.extend(sh.group.to_be_bytes());
                put_vec(&mut b, &sh.share);
                MsgType::ServerHello
            }
            Message::ServerVerify(sig) => {
                b.extend(sig);
                MsgType::ServerVerify
            }
            Message::Finished(mac) => {
                b.extend(mac);
                MsgType::Finished
            }
        };
        let mut out = Vec::with_capacity(4 + b.len());
        out.push(t as u8);
        out.extend(&(b.len() as u32).to_be_bytes()[1..]);
        out.extend(b);
        out
    }

    /// Decode exactly one complete framed message. Trailing bytes are an error.
    pub fn decode(buf: &[u8]) -> Result<Message, Error> {
        let mut r = Reader(buf);
        let t = r.u8()?;
        let len = r.u24()? as usize;
        if len > MAX_MESSAGE {
            return Err(Error::Decode("message too large"));
        }
        let mut r = Reader(r.take(len)?);
        if buf.len() != 4 + len {
            return Err(Error::Decode("trailing bytes after message"));
        }
        let msg = match t {
            1 => {
                let version = r.u16()?;
                let random = r.arr::<32>()?;
                let g = r.vec()?;
                if g.len() % 2 != 0 || g.is_empty() {
                    return Err(Error::Decode("bad group list"));
                }
                let groups = g
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                let n = r.u8()? as usize;
                if n == 0 || n > MAX_SHARES {
                    return Err(Error::Decode("bad key share count"));
                }
                let mut shares = Vec::with_capacity(n);
                for _ in 0..n {
                    let g = r.u16()?;
                    if shares.iter().any(|(x, _)| *x == g) {
                        return Err(Error::Decode("duplicate key share"));
                    }
                    shares.push((g, r.vec()?.to_vec()));
                }
                Message::ClientHello(ClientHello {
                    version,
                    random,
                    groups,
                    shares,
                })
            }
            2 => Message::ServerHello(ServerHello {
                version: r.u16()?,
                random: r.arr::<32>()?,
                group: r.u16()?,
                share: r.vec()?.to_vec(),
            }),
            15 => Message::ServerVerify(r.arr::<64>()?),
            20 => Message::Finished(r.arr::<32>()?),
            _ => return Err(Error::Decode("unknown message type")),
        };
        if !r.0.is_empty() {
            return Err(Error::Decode("trailing bytes in body"));
        }
        Ok(msg)
    }
}

fn put_vec(b: &mut Vec<u8>, v: &[u8]) {
    b.extend((v.len() as u16).to_be_bytes());
    b.extend(v);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Decode("truncated"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Result<u32, Error> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
    }
    fn vec(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

//! qh: keygen / echo server / client over TCP.
//!   qh keygen <secret-key-file>                  -> prints the public key (hex) to pin on clients
//!   qh server <addr> <secret-key-file> <groups>  -> echo server, one thread per connection
//!   qh client <addr> <server-pubkey-hex> <groups> <message> [--require-pq]
//! <groups> is a comma list in preference order: x25519mlkem768,mlkem768,x25519

use qhandshake::transport::{accept, connect, read_app, write_app};
use qhandshake::{ClientConfig, Group, ServerConfig};
use std::net::{TcpListener, TcpStream};
use std::process::exit;

fn groups(s: &str) -> Vec<Group> {
    s.split(',')
        .map(|g| match g {
            "x25519" => Group::X25519,
            "mlkem768" => Group::MlKem768,
            "x25519mlkem768" => Group::X25519MlKem768,
            _ => die(&format!("unknown group '{g}'")),
        })
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    let s = s.trim();
    if s.len() != 64 {
        die("expected 64 hex characters");
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_else(|_| die("invalid hex"));
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn die(msg: &str) -> ! {
    eprintln!("qh: {msg}");
    exit(2)
}

fn load_key(path: &str) -> ed25519_dalek::SigningKey {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
    ed25519_dalek::SigningKey::from_bytes(&hex32(&s))
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("keygen") if a.len() == 3 => {
            let sk = qhandshake::generate_identity();
            if std::path::Path::new(&a[2]).exists() {
                die("refusing to overwrite existing key file");
            }
            std::fs::write(&a[2], hex(&sk.to_bytes())).unwrap_or_else(|e| die(&e.to_string()));
            println!("{}", hex(sk.verifying_key().as_bytes()));
        }
        Some("server") if a.len() == 5 => {
            let sk = load_key(&a[3]);
            let accept_groups = groups(&a[4]);
            let l = TcpListener::bind(&a[2]).unwrap_or_else(|e| die(&e.to_string()));
            eprintln!(
                "listening on {} pubkey={}",
                a[2],
                hex(sk.verifying_key().as_bytes())
            );
            for conn in l.incoming() {
                let Ok(mut s) = conn else { continue };
                let cfg = ServerConfig {
                    accept: accept_groups.clone(),
                    signing_key: sk.clone(),
                };
                std::thread::spawn(move || {
                    let peer = s.peer_addr().ok();
                    let r = (|| {
                        let mut sv = accept(&mut s, cfg)?;
                        let group = sv.group();
                        let sess = sv.session().expect("connected");
                        let msg = read_app(&mut s, sess)?;
                        write_app(&mut s, sess, &msg)?;
                        Ok::<_, qhandshake::transport::TransportError>(group)
                    })();
                    match r {
                        Ok(g) => eprintln!("{peer:?}: ok group={g:?}"),
                        Err(e) => eprintln!("{peer:?}: handshake failed: {e}"),
                    }
                });
            }
        }
        Some("client") if a.len() == 6 || a.len() == 7 => {
            let key = ed25519_dalek::VerifyingKey::from_bytes(&hex32(&a[3]))
                .unwrap_or_else(|_| die("invalid public key"));
            let cfg = ClientConfig {
                offer: groups(&a[4]),
                server_key: key,
                require_pq: a.get(6).is_some_and(|f| f == "--require-pq"),
            };
            let mut s = TcpStream::connect(&a[2]).unwrap_or_else(|e| die(&e.to_string()));
            let r = (|| {
                let mut c = connect(&mut s, cfg)?;
                let group = c.group();
                let sess = c.session().expect("connected");
                write_app(&mut s, sess, a[5].as_bytes())?;
                Ok::<_, qhandshake::transport::TransportError>((group, read_app(&mut s, sess)?))
            })();
            match r {
                Ok((g, echo)) => println!("group={g:?} echo={}", String::from_utf8_lossy(&echo)),
                Err(e) => die(&format!("handshake failed: {e}")),
            }
        }
        _ => die(
            "usage: qh keygen <file> | qh server <addr> <keyfile> <groups> | qh client <addr> <pubkey-hex> <groups> <msg> [--require-pq]",
        ),
    }
}

//! Real sockets: two endpoints over loopback TCP, success and alert propagation.

use qhandshake::transport::{TransportError, accept, connect, read_app, write_app};
use qhandshake::{ClientConfig, Error, Group, ServerConfig};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn pair(
    offer: Vec<Group>,
    accept_groups: Vec<Group>,
) -> (Result<Vec<u8>, TransportError>, Result<(), TransportError>) {
    let sk = qhandshake::generate_identity();
    let pk = sk.verifying_key();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let server = thread::spawn(move || -> Result<(), TransportError> {
        let (mut s, _) = l.accept().unwrap();
        let mut sv = accept(
            &mut s,
            ServerConfig {
                accept: accept_groups,
                signing_key: sk,
            },
        )?;
        let sess = sv.session().unwrap();
        let m = read_app(&mut s, sess)?;
        write_app(&mut s, sess, &m)
    });
    let mut s = TcpStream::connect(addr).unwrap();
    let client = (|| {
        let mut c = connect(
            &mut s,
            ClientConfig {
                offer,
                server_key: pk,
                require_pq: false,
            },
        )?;
        let sess = c.session().unwrap();
        write_app(&mut s, sess, b"over tcp")?;
        read_app(&mut s, sess)
    })();
    (client, server.join().unwrap())
}

#[test]
fn hybrid_over_tcp_echoes() {
    let (c, s) = pair(vec![Group::X25519MlKem768], vec![Group::X25519MlKem768]);
    assert_eq!(c.unwrap(), b"over tcp");
    s.unwrap();
}

#[test]
fn no_common_group_reaches_client_as_alert() {
    let (c, s) = pair(vec![Group::MlKem768], vec![Group::X25519]);
    assert!(
        matches!(c, Err(TransportError::Protocol(Error::PeerAlert(40)))),
        "{c:?}"
    );
    assert!(matches!(
        s,
        Err(TransportError::Protocol(Error::HandshakeFailure(_)))
    ));
}

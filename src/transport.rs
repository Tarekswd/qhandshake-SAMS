//! Blocking TCP transport. Reuses the handshake framing (`type | u24 len | body`); application data
//! records use type 23. Reads are bounded by `codec::MAX_MESSAGE` and a socket timeout.

use crate::codec::MAX_MESSAGE;
use crate::{Client, ClientConfig, ClientState, Error, Server, ServerConfig, ServerState, Session};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const APP_DATA: u8 = 23;
pub const ALERT: u8 = 21;
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Protocol(#[from] Error),
}

/// Read one framed message, returning the raw bytes including the 4-byte header.
pub fn read_frame(s: &mut impl Read) -> Result<Vec<u8>, TransportError> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h)?;
    let len = u32::from_be_bytes([0, h[1], h[2], h[3]]) as usize;
    if len > MAX_MESSAGE {
        return Err(Error::Decode("frame too large").into());
    }
    let mut buf = h.to_vec();
    buf.resize(4 + len, 0);
    s.read_exact(&mut buf[4..])?;
    if buf[0] == ALERT && len == 1 {
        return Err(Error::PeerAlert(buf[4]).into());
    }
    Ok(buf)
}

/// Best-effort: tell the peer why we are closing. Write errors are ignored because the
/// connection is being torn down and the original error is what gets reported.
fn send_alert(s: &mut impl Write, e: &TransportError) {
    if let TransportError::Protocol(e) = e
        && !matches!(e, Error::PeerAlert(_))
    {
        let _ = s.write_all(&[ALERT, 0, 0, 1, e.alert_code()]);
    }
}

pub fn write_app(
    s: &mut impl Write,
    sess: &mut Session,
    data: &[u8],
) -> Result<(), TransportError> {
    let ct = sess.seal(data)?;
    if ct.len() > MAX_MESSAGE {
        return Err(Error::Config("record too large").into());
    }
    let mut f = vec![APP_DATA];
    f.extend(&(ct.len() as u32).to_be_bytes()[1..]);
    f.extend(ct);
    s.write_all(&f)?;
    Ok(())
}

pub fn read_app(s: &mut impl Read, sess: &mut Session) -> Result<Vec<u8>, TransportError> {
    let f = read_frame(s)?;
    if f[0] != APP_DATA {
        return Err(Error::UnexpectedMessage("expected application data").into());
    }
    Ok(sess.open(&f[4..])?)
}

fn prep(s: &TcpStream) -> io::Result<()> {
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    s.set_write_timeout(Some(IO_TIMEOUT))?;
    s.set_nodelay(true)
}

pub fn connect(s: &mut TcpStream, cfg: ClientConfig) -> Result<Client, TransportError> {
    prep(s)?;
    let (mut c, ch) = Client::new(cfg)?;
    s.write_all(&ch)?;
    let r = (|| {
        while c.state() != ClientState::Connected {
            for out in c.handle(&read_frame(s)?)? {
                s.write_all(&out)?;
            }
        }
        Ok(())
    })();
    r.inspect_err(|e| send_alert(s, e))?;
    Ok(c)
}

pub fn accept(s: &mut TcpStream, cfg: ServerConfig) -> Result<Server, TransportError> {
    prep(s)?;
    let mut sv = Server::new(cfg)?;
    let r = (|| {
        while sv.state() != ServerState::Connected {
            let mut flight = Vec::new();
            for out in sv.handle(&read_frame(s)?)? {
                flight.extend(out);
            }
            s.write_all(&flight)?;
        }
        Ok(())
    })();
    r.inspect_err(|e| send_alert(s, e))?;
    Ok(sv)
}

//! Noise_XX_25519_ChaChaPoly_BLAKE2s handshake and encrypted, length-framed transport.
//!
//! Both peers authenticate with long-term static keys; the application verifies the peer's
//! key fingerprint (see `identity`) before any input message is accepted.

use crate::identity::{fingerprint, Identity};
use crate::proto::{decode, encode, Msg};
use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NOISE_PARAMS: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
const MAX_FRAME: usize = 4096;

pub struct SecureReader {
    stream: TcpStream,
    ts: Arc<snow::StatelessTransportState>,
    nonce: u64,
}

#[derive(Clone)]
pub struct SecureWriter {
    inner: Arc<Mutex<WriterInner>>,
}

struct WriterInner {
    stream: TcpStream,
    ts: Arc<snow::StatelessTransportState>,
    nonce: u64,
}

pub struct Established {
    pub reader: SecureReader,
    pub writer: SecureWriter,
    pub peer_fingerprint: String,
}

fn write_frame(s: &mut TcpStream, data: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(data.len() + 2);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    s.write_all(&buf)?; // single write: header + body in one segment
    Ok(())
}

fn read_frame(s: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len)?;
    let n = u16::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        bail!("frame too large");
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

/// Run the handshake on `stream`. `psk` is derived from the shared security key
/// (see `identity::psk_from_key`): a wrong key makes the handshake fail before any
/// application data flows. `idle_timeout` bounds every later read (keepalive).
pub fn handshake(
    mut stream: TcpStream,
    id: &Identity,
    initiator: bool,
    idle_timeout: Duration,
    psk: &[u8; 32],
) -> Result<Established> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let params = NOISE_PARAMS.parse()?;
    let builder = snow::Builder::new(params).local_private_key(&id.private).psk(3, psk);
    let mut hs = if initiator { builder.build_initiator()? } else { builder.build_responder()? };
    let mut buf = vec![0u8; 1024];
    let mut my_turn = initiator;
    while !hs.is_handshake_finished() {
        if my_turn {
            let n = hs.write_message(&[], &mut buf)?;
            write_frame(&mut stream, &buf[..n])?;
        } else {
            let msg = read_frame(&mut stream).context("handshake read")?;
            hs.read_message(&msg, &mut buf)?;
        }
        my_turn = !my_turn;
    }
    let remote = hs.get_remote_static().context("no remote static key")?.to_vec();
    let ts = Arc::new(hs.into_stateless_transport_mode()?);
    stream.set_read_timeout(Some(idle_timeout))?;
    let reader = SecureReader { stream: stream.try_clone()?, ts: ts.clone(), nonce: 0 };
    let writer = SecureWriter {
        inner: Arc::new(Mutex::new(WriterInner { stream, ts, nonce: 0 })),
    };
    Ok(Established { reader, writer, peer_fingerprint: fingerprint(&remote) })
}

impl SecureWriter {
    pub fn send(&self, msg: &Msg) -> Result<()> {
        let plain = encode(msg)?;
        let mut g = self.inner.lock().unwrap();
        let mut out = vec![0u8; plain.len() + 16];
        let n = g.ts.write_message(g.nonce, &plain, &mut out)?;
        g.nonce += 1;
        write_frame(&mut g.stream, &out[..n])
    }

    pub fn shutdown(&self) {
        let g = self.inner.lock().unwrap();
        let _ = g.stream.shutdown(std::net::Shutdown::Both);
    }
}

impl SecureReader {
    pub fn recv(&mut self) -> Result<Msg> {
        let frame = read_frame(&mut self.stream)?;
        let mut out = vec![0u8; frame.len()];
        let n = self.ts.read_message(self.nonce, &frame, &mut out)?;
        self.nonce += 1;
        decode(&out[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::InputEv;
    use std::net::TcpListener;

    fn handshake(s: TcpStream, id: &Identity, init: bool, t: Duration) -> Result<Established> {
        super::handshake(s, id, init, t, &[7u8; 32])
    }

    #[test]
    fn wrong_security_key_fails_handshake() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let b = Identity::generate().unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            super::handshake(s, &b, false, Duration::from_secs(5), &[1u8; 32]).is_err()
        });
        let a = Identity::generate().unwrap();
        let c = super::handshake(TcpStream::connect(addr).unwrap(), &a, true, Duration::from_secs(5), &[2u8; 32]);
        let server_failed = t.join().unwrap();
        assert!(server_failed, "server must reject a client with a different key");
        drop(c);
    }

    fn pair() -> (Established, Established) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let (fa, fb) = (a.fingerprint(), b.fingerprint());
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let e = handshake(s, &b, false, Duration::from_secs(5)).unwrap();
            assert_eq!(e.peer_fingerprint, fa);
            e
        });
        let c = handshake(TcpStream::connect(addr).unwrap(), &a, true, Duration::from_secs(5)).unwrap();
        assert_eq!(c.peer_fingerprint, fb);
        (c, t.join().unwrap())
    }

    #[test]
    fn encrypted_roundtrip() {
        let (mut c, mut s) = pair();
        let m = Msg::Input(InputEv::MouseRel { dx: 4, dy: 5 });
        c.writer.send(&m).unwrap();
        assert_eq!(s.reader.recv().unwrap(), m);
        s.writer.send(&Msg::Bye).unwrap();
        assert_eq!(c.reader.recv().unwrap(), Msg::Bye);
    }

    #[test]
    fn tampered_frame_is_rejected() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            handshake(s, &b, false, Duration::from_secs(5)).unwrap()
        });
        let c = handshake(TcpStream::connect(addr).unwrap(), &a, true, Duration::from_secs(5)).unwrap();
        let mut s = t.join().unwrap();
        // Write a forged frame directly on the raw socket.
        {
            let mut g = c.writer.inner.lock().unwrap();
            write_frame(&mut g.stream, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]).unwrap();
        }
        assert!(s.reader.recv().is_err());
    }
}

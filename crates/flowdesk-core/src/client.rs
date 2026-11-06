//! Client side: receives input from the host and injects it locally.

use crate::backend::{Event, Injector, Verifier};
use crate::identity::{Identity, TrustStore};
use crate::proto::{InputEv, Msg, Side, PROTOCOL_VERSION};
use crate::secure::{handshake, SecureWriter};
use anyhow::{bail, Result};
use rdev::{Button, Key};
use std::collections::HashSet;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Pure state machine: virtual cursor, edge hand-back, stuck-key protection.
pub struct ClientCore<I: Injector> {
    inj: I,
    w: f64,
    h: f64,
    active: bool,
    edge: Side,
    pos: (f64, f64),
    keys: HashSet<Key>,
    buttons: HashSet<Button>,
}

impl<I: Injector> ClientCore<I> {
    pub fn new(inj: I) -> Self {
        let (w, h) = inj.screen_size();
        ClientCore {
            inj,
            w,
            h,
            active: false,
            edge: Side::Left,
            pos: (0.0, 0.0),
            keys: HashSet::new(),
            buttons: HashSet::new(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }
    pub fn position(&self) -> (f64, f64) {
        self.pos
    }
    pub fn screen(&self) -> (f64, f64) {
        (self.w, self.h)
    }

    fn release_all(&mut self) {
        for k in self.keys.drain().collect::<Vec<_>>() {
            self.inj.key(k, false);
        }
        for b in self.buttons.drain().collect::<Vec<_>>() {
            self.inj.button(b, false);
        }
    }

    /// Handle a message from the host; returns an optional reply.
    pub fn handle(&mut self, msg: &Msg) -> Option<Msg> {
        match msg {
            Msg::Enter { edge, frac } => {
                let f = (*frac as f64).clamp(0.0, 1.0);
                self.edge = *edge;
                self.pos = match edge {
                    Side::Left => (1.0, f * (self.h - 1.0)),
                    Side::Right => (self.w - 2.0, f * (self.h - 1.0)),
                    Side::Top => (f * (self.w - 1.0), 1.0),
                    Side::Bottom => (f * (self.w - 1.0), self.h - 2.0),
                };
                self.active = true;
                self.inj.mouse_abs(self.pos.0, self.pos.1);
                None
            }
            Msg::ReleaseAll => {
                self.release_all();
                self.active = false;
                None
            }
            Msg::Ping { id, sent_us } => Some(Msg::Pong { id: *id, sent_us: *sent_us }),
            Msg::Input(ev) if self.active => self.input(ev),
            _ => None,
        }
    }

    fn input(&mut self, ev: &InputEv) -> Option<Msg> {
        match ev {
            InputEv::MouseRel { dx, dy } => {
                let nx = self.pos.0 + *dx as f64;
                let ny = self.pos.1 + *dy as f64;
                let leaving = match self.edge {
                    Side::Left => nx < 0.0,
                    Side::Right => nx > self.w - 1.0,
                    Side::Top => ny < 0.0,
                    Side::Bottom => ny > self.h - 1.0,
                };
                self.pos = (nx.clamp(0.0, self.w - 1.0), ny.clamp(0.0, self.h - 1.0));
                if leaving {
                    let frac = match self.edge {
                        Side::Left | Side::Right => self.pos.1 / (self.h - 1.0),
                        _ => self.pos.0 / (self.w - 1.0),
                    };
                    self.release_all();
                    self.active = false;
                    return Some(Msg::Leave { frac: frac as f32 });
                }
                self.inj.mouse_abs(self.pos.0, self.pos.1);
            }
            InputEv::Button { button, down } => {
                if *down {
                    self.buttons.insert(*button);
                } else {
                    self.buttons.remove(button);
                }
                self.inj.button(*button, *down);
            }
            InputEv::Wheel { dx, dy } => self.inj.wheel(*dx, *dy),
            InputEv::Key { key, down } => {
                if *down {
                    self.keys.insert(*key);
                } else {
                    self.keys.remove(key);
                }
                self.inj.key(*key, *down);
            }
        }
        None
    }
}

pub struct ClientConfig {
    /// `host:port` — hostname or IP (works across VPNs; no discovery involved).
    pub host: String,
    pub name: String,
}

#[derive(Clone)]
pub struct ClientHandle {
    stop: Arc<AtomicBool>,
    writer: Arc<Mutex<Option<SecureWriter>>>,
}

impl ClientHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(w) = self.writer.lock().unwrap().as_ref() {
            let _ = w.send(&Msg::Bye);
            w.shutdown();
        }
    }
}

fn connect(host: &str) -> Result<TcpStream> {
    let mut last = None;
    for a in host.to_socket_addrs()? {
        match TcpStream::connect_timeout(&a, Duration::from_secs(5)) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    match last {
        Some(e) => Err(e.into()),
        None => bail!("could not resolve {host}"),
    }
}

/// Connect to a host (retrying with backoff) and inject its input until stopped.
pub fn start_client(
    cfg: ClientConfig,
    id: Identity,
    trust: Arc<Mutex<TrustStore>>,
    verifier: Arc<dyn Verifier>,
    injector: Box<dyn Injector>,
    events: Sender<Event>,
) -> ClientHandle {
    let handle = ClientHandle { stop: Arc::new(AtomicBool::new(false)), writer: Arc::new(Mutex::new(None)) };
    let h = handle.clone();
    std::thread::spawn(move || {
        let (w, hh) = injector.screen_size();
        let mut core = ClientCore::new(BoxedInjector(injector));
        let mut backoff = 500u64;
        while !h.stop.load(Ordering::SeqCst) {
            let _ = events.send(Event::Log(format!("Connecting to {} ...", cfg.host)));
            match session(&cfg, &id, &trust, &verifier, &mut core, (w, hh), &h, &events) {
                Ok(true) => backoff = 500,
                Ok(false) => {}
                Err(e) => {
                    let _ = events.send(Event::Log(format!("Connection failed: {e:#}")));
                }
            }
            *h.writer.lock().unwrap() = None;
            let _ = core.handle(&Msg::ReleaseAll);
            if h.stop.load(Ordering::SeqCst) {
                break;
            }
            let _ = events.send(Event::Log(format!("Retrying in {:.1}s", backoff as f64 / 1000.0)));
            let mut waited = 0;
            while waited < backoff && !h.stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(100));
                waited += 100;
            }
            backoff = (backoff * 2).min(5000);
        }
        let _ = events.send(Event::Log("Client stopped".into()));
    });
    handle
}

struct BoxedInjector(Box<dyn Injector>);
impl Injector for BoxedInjector {
    fn mouse_abs(&mut self, x: f64, y: f64) {
        self.0.mouse_abs(x, y)
    }
    fn button(&mut self, b: Button, d: bool) {
        self.0.button(b, d)
    }
    fn wheel(&mut self, dx: i64, dy: i64) {
        self.0.wheel(dx, dy)
    }
    fn key(&mut self, k: Key, d: bool) {
        self.0.key(k, d)
    }
    fn screen_size(&self) -> (f64, f64) {
        self.0.screen_size()
    }
}

/// Returns Ok(true) if a session was established (so backoff resets).
#[allow(clippy::too_many_arguments)]
fn session(
    cfg: &ClientConfig,
    id: &Identity,
    trust: &Arc<Mutex<TrustStore>>,
    verifier: &Arc<dyn Verifier>,
    core: &mut ClientCore<BoxedInjector>,
    screen: (f64, f64),
    handle: &ClientHandle,
    events: &Sender<Event>,
) -> Result<bool> {
    let stream = connect(&cfg.host)?;
    let mut est = handshake(stream, id, true, Duration::from_secs(6))?;
    if !crate::host::check_peer(trust, verifier, &est.peer_fingerprint, &cfg.host) {
        let _ = events.send(Event::Log(format!("Host {} rejected (untrusted)", est.peer_fingerprint)));
        est.writer.shutdown();
        bail!("host not trusted");
    }
    *handle.writer.lock().unwrap() = Some(est.writer.clone());
    let host_name = match est.reader.recv()? {
        Msg::Hello { name, version, .. } => {
            if version != PROTOCOL_VERSION {
                bail!("protocol version mismatch");
            }
            name
        }
        _ => bail!("expected Hello"),
    };
    est.writer.send(&Msg::Hello {
        version: PROTOCOL_VERSION,
        name: cfg.name.clone(),
        width: screen.0 as u32,
        height: screen.1 as u32,
    })?;
    trust.lock().unwrap().trust(&est.peer_fingerprint, &host_name);
    let _ = events.send(Event::PeerConnected { name: host_name.clone(), fingerprint: est.peer_fingerprint.clone() });
    loop {
        let msg = match est.reader.recv() {
            Ok(m) => m,
            Err(e) => {
                let _ = events.send(Event::PeerDisconnected { name: host_name });
                if handle.stop.load(Ordering::SeqCst) {
                    return Ok(true);
                }
                return Err(e);
            }
        };
        if msg == Msg::Bye {
            let _ = events.send(Event::PeerDisconnected { name: host_name });
            return Ok(true);
        }
        let was_active = core.is_active();
        if let Some(reply) = core.handle(&msg) {
            est.writer.send(&reply)?;
        }
        if was_active != core.is_active() {
            let _ = events.send(Event::Control(core.is_active().then(|| "this computer".to_string())));
        } else if matches!(msg, Msg::Enter { .. }) {
            let _ = events.send(Event::Control(Some("this computer".into())));
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[derive(Default, Debug, Clone, PartialEq)]
    pub struct Rec(pub Vec<String>);

    pub struct MockInj(pub Arc<Mutex<Rec>>);
    impl Injector for MockInj {
        fn mouse_abs(&mut self, x: f64, y: f64) {
            self.0.lock().unwrap().0.push(format!("move {x:.0},{y:.0}"));
        }
        fn button(&mut self, b: Button, d: bool) {
            self.0.lock().unwrap().0.push(format!("btn {b:?} {d}"));
        }
        fn wheel(&mut self, dx: i64, dy: i64) {
            self.0.lock().unwrap().0.push(format!("wheel {dx},{dy}"));
        }
        fn key(&mut self, k: Key, d: bool) {
            self.0.lock().unwrap().0.push(format!("key {k:?} {d}"));
        }
        fn screen_size(&self) -> (f64, f64) {
            (1000.0, 500.0)
        }
    }

    fn core() -> (ClientCore<MockInj>, Arc<Mutex<Rec>>) {
        let rec = Arc::new(Mutex::new(Rec::default()));
        (ClientCore::new(MockInj(rec.clone())), rec)
    }

    #[test]
    fn ignores_input_when_not_active() {
        let (mut c, rec) = core();
        c.handle(&Msg::Input(InputEv::Key { key: Key::KeyA, down: true }));
        assert!(rec.lock().unwrap().0.is_empty());
    }

    #[test]
    fn enter_moves_and_relative_motion_applies() {
        let (mut c, rec) = core();
        c.handle(&Msg::Enter { edge: Side::Left, frac: 0.0 });
        assert!(c.is_active());
        c.handle(&Msg::Input(InputEv::MouseRel { dx: 10, dy: 5 }));
        let r = rec.lock().unwrap().0.clone();
        assert_eq!(r[0], "move 1,0");
        assert_eq!(r[1], "move 11,5");
    }

    #[test]
    fn leaving_through_entry_edge_returns_control_and_releases_keys() {
        let (mut c, rec) = core();
        c.handle(&Msg::Enter { edge: Side::Left, frac: 0.0 });
        c.handle(&Msg::Input(InputEv::Key { key: Key::ShiftLeft, down: true }));
        let reply = c.handle(&Msg::Input(InputEv::MouseRel { dx: -50, dy: 0 }));
        assert!(matches!(reply, Some(Msg::Leave { .. })));
        assert!(!c.is_active());
        assert!(rec.lock().unwrap().0.iter().any(|s| s == "key ShiftLeft false"));
    }

    #[test]
    fn other_edges_clamp_instead_of_leaving() {
        let (mut c, _) = core();
        c.handle(&Msg::Enter { edge: Side::Left, frac: 0.5 });
        let r = c.handle(&Msg::Input(InputEv::MouseRel { dx: 5000, dy: 5000 }));
        assert!(r.is_none());
        assert_eq!(c.position(), (999.0, 499.0));
    }

    #[test]
    fn ping_is_answered_even_when_inactive() {
        let (mut c, _) = core();
        assert_eq!(c.handle(&Msg::Ping { id: 3, sent_us: 9 }), Some(Msg::Pong { id: 3, sent_us: 9 }));
    }

    #[test]
    fn release_all_clears_pressed() {
        let (mut c, rec) = core();
        c.handle(&Msg::Enter { edge: Side::Top, frac: 0.5 });
        c.handle(&Msg::Input(InputEv::Button { button: Button::Left, down: true }));
        c.handle(&Msg::ReleaseAll);
        assert!(rec.lock().unwrap().0.iter().any(|s| s == "btn Left false"));
        assert!(!c.is_active());
    }
}

//! Host side: owns the physical keyboard/mouse, decides when control moves to a client.

use crate::backend::{Event, RawEvent, Verifier, Warp};
use crate::identity::{Identity, TrustStore};
use crate::proto::{try_merge, InputEv, Msg, Side, PROTOCOL_VERSION};
use crate::secure::{handshake, SecureWriter};
use crate::stats::{LatencyStats, Summary};
use anyhow::{bail, Result};
use rdev::Key;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const EDGE_INSET: f64 = 24.0;
const IDLE_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_PENDING: usize = 8;

/// Trust check shared by host and client: known fingerprints pass, others ask the verifier.
pub fn check_peer(
    trust: &Arc<Mutex<TrustStore>>,
    verifier: &Arc<dyn Verifier>,
    fp: &str,
    addr: &str,
) -> bool {
    if trust.lock().unwrap().is_trusted(fp) {
        return true;
    }
    verifier.confirm(fp, addr)
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: u64,
    pub name: String,
    pub fingerprint: String,
    pub width: u32,
    pub height: u32,
    pub side: Option<Side>,
    pub rtt: Summary,
}

struct Peer {
    info: PeerInfo,
    writer: SecureWriter,
    stats: LatencyStats,
}

#[derive(PartialEq, Clone, Copy)]
enum Control {
    Local,
    Remote(u64),
}

struct State {
    peers: Vec<Peer>,
    layout: HashMap<String, Side>,
    control: Control,
    ctrl: bool,
    alt: bool,
    pending_warp: u32,
    next_id: u64,
}

pub struct Host {
    name: String,
    id: Identity,
    trust: Arc<Mutex<TrustStore>>,
    verifier: Arc<dyn Verifier>,
    screen: (f64, f64),
    warp: Warp,
    events: Sender<Event>,
    state: Mutex<State>,
    out: Mutex<Sender<(u64, Msg)>>,
    stop: AtomicBool,
    pending_conns: AtomicUsize,
    epoch: Instant,
}

impl Host {
    pub fn new(
        name: String,
        id: Identity,
        trust: Arc<Mutex<TrustStore>>,
        verifier: Arc<dyn Verifier>,
        screen: (f64, f64),
        warp: Warp,
        events: Sender<Event>,
        layout: HashMap<String, Side>,
    ) -> Arc<Host> {
        let (tx, rx) = channel();
        let host = Arc::new(Host {
            name,
            id,
            trust,
            verifier,
            screen,
            warp,
            events,
            state: Mutex::new(State {
                peers: vec![],
                layout,
                control: Control::Local,
                ctrl: false,
                alt: false,
                pending_warp: 0,
                next_id: 1,
            }),
            out: Mutex::new(tx),
            stop: AtomicBool::new(false),
            pending_conns: AtomicUsize::new(0),
            epoch: Instant::now(),
        });
        let h = host.clone();
        std::thread::spawn(move || h.sender_loop(rx));
        let h = host.clone();
        std::thread::spawn(move || h.ping_loop());
        host
    }

    fn log(&self, s: impl Into<String>) {
        let _ = self.events.send(Event::Log(s.into()));
    }

    /// Start accepting clients. Returns the bound address.
    pub fn listen(self: &Arc<Self>, addr: &str) -> Result<SocketAddr> {
        let l = TcpListener::bind(addr)?;
        l.set_nonblocking(true)?;
        let bound = l.local_addr()?;
        self.log(format!("Listening on {bound}"));
        let me = self.clone();
        std::thread::spawn(move || {
            while !me.stop.load(Ordering::SeqCst) {
                match l.accept() {
                    Ok((s, peer)) => {
                        let _ = s.set_nonblocking(false);
                        if me.pending_conns.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING {
                            me.pending_conns.fetch_sub(1, Ordering::SeqCst);
                            continue;
                        }
                        let me2 = me.clone();
                        std::thread::spawn(move || {
                            if let Err(e) = me2.serve(s, peer) {
                                me2.log(format!("{peer}: {e:#}"));
                            }
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(200)),
                }
            }
        });
        Ok(bound)
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.return_control();
        let st = self.state.lock().unwrap();
        for p in &st.peers {
            let _ = p.writer.send(&Msg::Bye);
            p.writer.shutdown();
        }
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        let st = self.state.lock().unwrap();
        st.peers
            .iter()
            .map(|p| PeerInfo { rtt: p.stats.summary(), ..p.info.clone() })
            .collect()
    }

    pub fn rtt_history(&self, id: u64) -> Vec<u64> {
        let st = self.state.lock().unwrap();
        st.peers.iter().find(|p| p.info.id == id).map(|p| p.stats.history()).unwrap_or_default()
    }

    pub fn layout(&self) -> HashMap<String, Side> {
        self.state.lock().unwrap().layout.clone()
    }

    /// Assign (or clear) the screen edge where a peer sits. A side holds one peer.
    pub fn set_side(&self, fp: &str, side: Option<Side>) {
        let mut st = self.state.lock().unwrap();
        if let Some(s) = side {
            st.layout.retain(|k, v| !(*v == s && k != fp));
        }
        match side {
            Some(s) => {
                st.layout.insert(fp.to_string(), s);
            }
            None => {
                st.layout.remove(fp);
            }
        }
        let layout = st.layout.clone();
        for p in st.peers.iter_mut() {
            p.info.side = layout.get(&p.info.fingerprint).copied();
        }
    }

    /// Send a ping to every peer immediately (used by diagnostics and benchmarks).
    pub fn ping_now(&self) {
        let writers: Vec<SecureWriter> =
            self.state.lock().unwrap().peers.iter().map(|p| p.writer.clone()).collect();
        for w in writers {
            if w.send(&Msg::Ping { id: 0, sent_us: self.now_us() }).is_err() {
                w.shutdown();
            }
        }
    }

    pub fn is_remote(&self) -> bool {
        matches!(self.state.lock().unwrap().control, Control::Remote(_))
    }

    fn now_us(&self) -> u64 {
        self.epoch.elapsed().as_micros() as u64
    }

    fn serve(self: &Arc<Self>, stream: std::net::TcpStream, addr: SocketAddr) -> Result<()> {
        struct Guard<'a>(&'a AtomicUsize, bool);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                if !self.1 {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
        let mut guard = Guard(&self.pending_conns, false);
        let mut est = handshake(stream, &self.id, false, IDLE_TIMEOUT)?;
        let fp = est.peer_fingerprint.clone();
        if !check_peer(&self.trust, &self.verifier, &fp, &addr.to_string()) {
            est.writer.shutdown();
            bail!("rejected untrusted peer {fp}");
        }
        est.writer.send(&Msg::Hello {
            version: PROTOCOL_VERSION,
            name: self.name.clone(),
            width: self.screen.0 as u32,
            height: self.screen.1 as u32,
        })?;
        let (name, width, height) = match est.reader.recv()? {
            Msg::Hello { version, name, width, height } if version == PROTOCOL_VERSION => (name, width, height),
            _ => bail!("bad Hello / version mismatch"),
        };
        self.trust.lock().unwrap().trust(&fp, &name);
        // Fully connected: no longer counts as a pending (unauthenticated) connection.
        self.pending_conns.fetch_sub(1, Ordering::SeqCst);
        guard.1 = true;

        let id = {
            let mut st = self.state.lock().unwrap();
            let id = st.next_id;
            st.next_id += 1;
            let side = match st.layout.get(&fp).copied() {
                Some(s) => Some(s),
                None => {
                    let free = [Side::Right, Side::Left, Side::Top, Side::Bottom]
                        .into_iter()
                        .find(|s| !st.layout.values().any(|v| v == s));
                    if let Some(s) = free {
                        st.layout.insert(fp.clone(), s);
                    }
                    free
                }
            };
            st.peers.push(Peer {
                info: PeerInfo {
                    id,
                    name: name.clone(),
                    fingerprint: fp.clone(),
                    width,
                    height,
                    side,
                    rtt: Summary::default(),
                },
                writer: est.writer.clone(),
                stats: LatencyStats::default(),
            });
            id
        };
        let _ = self.events.send(Event::PeerConnected { name: name.clone(), fingerprint: fp });

        let result = loop {
            match est.reader.recv() {
                Ok(Msg::Pong { sent_us, .. }) => {
                    let rtt = self.now_us().saturating_sub(sent_us);
                    if let Some(p) = self.state.lock().unwrap().peers.iter_mut().find(|p| p.info.id == id) {
                        p.stats.record(rtt);
                    }
                    let _ = self.events.send(Event::Rtt { peer: name.clone(), us: rtt });
                }
                Ok(Msg::Leave { frac }) => self.client_left(id, frac),
                Ok(Msg::Bye) => break Ok(()),
                Ok(_) => {}
                Err(e) => break Err(e),
            }
        };
        self.remove_peer(id);
        let _ = self.events.send(Event::PeerDisconnected { name });
        result
    }

    fn remove_peer(&self, id: u64) {
        let warp_center;
        {
            let mut st = self.state.lock().unwrap();
            st.peers.retain(|p| p.info.id != id);
            warp_center = st.control == Control::Remote(id);
            if warp_center {
                st.control = Control::Local;
            }
        }
        if warp_center {
            (self.warp)(self.screen.0 / 2.0, self.screen.1 / 2.0);
            let _ = self.events.send(Event::Control(None));
        }
    }

    fn queue(&self, id: u64, msg: Msg) {
        let _ = self.out.lock().unwrap().send((id, msg));
    }

    /// Writes queued messages; whatever piled up while the socket was busy is merged, so
    /// a slow link produces fewer, larger moves rather than a growing delay.
    fn sender_loop(self: Arc<Self>, rx: Receiver<(u64, Msg)>) {
        while let Ok(first) = rx.recv() {
            let mut batch: Vec<(u64, Msg)> = vec![first];
            while let Ok(m) = rx.try_recv() {
                batch.push(m);
            }
            let mut merged: Vec<(u64, Msg)> = Vec::with_capacity(batch.len());
            for (id, m) in batch {
                if let (Msg::Input(new), Some((lid, Msg::Input(last)))) = (&m, merged.last_mut()) {
                    if *lid == id && try_merge(last, new) {
                        continue;
                    }
                }
                merged.push((id, m));
            }
            for (id, m) in merged {
                let w = {
                    let st = self.state.lock().unwrap();
                    st.peers.iter().find(|p| p.info.id == id).map(|p| p.writer.clone())
                };
                if let Some(w) = w {
                    if w.send(&m).is_err() {
                        w.shutdown();
                    }
                }
            }
        }
    }

    fn ping_loop(self: Arc<Self>) {
        let mut n = 0u64;
        while !self.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(500));
            n += 1;
            let writers: Vec<SecureWriter> =
                self.state.lock().unwrap().peers.iter().map(|p| p.writer.clone()).collect();
            for w in writers {
                if w.send(&Msg::Ping { id: n, sent_us: self.now_us() }).is_err() {
                    w.shutdown();
                }
            }
        }
    }

    fn client_left(&self, id: u64, frac: f32) {
        let target;
        {
            let mut st = self.state.lock().unwrap();
            if st.control != Control::Remote(id) {
                return;
            }
            st.control = Control::Local;
            let side = st.peers.iter().find(|p| p.info.id == id).and_then(|p| p.info.side);
            let f = (frac as f64).clamp(0.0, 1.0);
            let (w, h) = self.screen;
            target = match side {
                Some(Side::Left) => (EDGE_INSET, f * (h - 1.0)),
                Some(Side::Right) => (w - 1.0 - EDGE_INSET, f * (h - 1.0)),
                Some(Side::Top) => (f * (w - 1.0), EDGE_INSET),
                Some(Side::Bottom) => (f * (w - 1.0), h - 1.0 - EDGE_INSET),
                None => (w / 2.0, h / 2.0),
            };
        }
        (self.warp)(target.0, target.1);
        let _ = self.events.send(Event::Control(None));
    }

    /// Panic button / hotkey: give input back to this computer immediately.
    pub fn return_control(&self) {
        let peer;
        {
            let mut st = self.state.lock().unwrap();
            match st.control {
                Control::Remote(id) => peer = id,
                Control::Local => return,
            }
            st.control = Control::Local;
        }
        self.queue(peer, Msg::ReleaseAll);
        (self.warp)(self.screen.0 / 2.0, self.screen.1 / 2.0);
        self.log("Control returned to this computer");
        let _ = self.events.send(Event::Control(None));
    }

    /// Feed one captured event. Returns `true` if the event must be swallowed locally.
    /// Hotkey: Ctrl+Alt+Pause returns control.
    pub fn on_raw(&self, ev: RawEvent) -> bool {
        let (cx, cy) = (self.screen.0 / 2.0, self.screen.1 / 2.0);
        let mut warp_to = None;
        let mut hotkey = false;
        let swallow;
        let mut control_event = None;
        {
            let mut st = self.state.lock().unwrap();
            if let RawEvent::Key { key, down } = &ev {
                match key {
                    Key::ControlLeft | Key::ControlRight => st.ctrl = *down,
                    Key::Alt | Key::AltGr => st.alt = *down,
                    Key::Pause if *down && st.ctrl && st.alt => hotkey = true,
                    _ => {}
                }
            }
            match st.control {
                _ if hotkey => swallow = st.control != Control::Local,
                Control::Local => {
                    swallow = false;
                    if let RawEvent::Move { x, y } = ev {
                        if let Some((peer, side, frac)) = self.edge_hit(&st, x, y) {
                            st.control = Control::Remote(peer);
                            st.pending_warp = 3;
                            warp_to = Some((cx, cy));
                            let name = st.peers.iter().find(|p| p.info.id == peer).map(|p| p.info.name.clone());
                            control_event = Some(name);
                            self.queue(peer, Msg::Enter { edge: side.opposite(), frac: frac as f32 });
                        }
                    }
                }
                Control::Remote(peer) => {
                    swallow = true;
                    match ev {
                        RawEvent::Move { x, y } => {
                            if st.pending_warp > 0 {
                                if (x - cx).abs() <= 1.0 && (y - cy).abs() <= 1.0 {
                                    st.pending_warp = 0;
                                } else {
                                    st.pending_warp -= 1;
                                }
                            } else {
                                let (dx, dy) = ((x - cx).round() as i32, (y - cy).round() as i32);
                                if dx != 0 || dy != 0 {
                                    self.queue(peer, Msg::Input(InputEv::MouseRel { dx, dy }));
                                }
                            }
                        }
                        RawEvent::Button { button, down } => {
                            self.queue(peer, Msg::Input(InputEv::Button { button, down }))
                        }
                        RawEvent::Wheel { dx, dy } => self.queue(peer, Msg::Input(InputEv::Wheel { dx, dy })),
                        RawEvent::Key { key, down } => self.queue(peer, Msg::Input(InputEv::Key { key, down })),
                    }
                }
            }
        }
        if hotkey {
            self.return_control();
            return swallow;
        }
        if let Some(name) = control_event {
            let _ = self.events.send(Event::Control(name));
        }
        if let Some((x, y)) = warp_to {
            (self.warp)(x, y);
        }
        swallow
    }

    fn edge_hit(&self, st: &State, x: f64, y: f64) -> Option<(u64, Side, f64)> {
        let (w, h) = self.screen;
        let side = if x <= 0.0 {
            Side::Left
        } else if x >= w - 1.0 {
            Side::Right
        } else if y <= 0.0 {
            Side::Top
        } else if y >= h - 1.0 {
            Side::Bottom
        } else {
            return None;
        };
        let peer = st.peers.iter().find(|p| p.info.side == Some(side))?;
        let frac = match side {
            Side::Left | Side::Right => y / (h - 1.0),
            _ => x / (w - 1.0),
        };
        Some((peer.info.id, side, frac.clamp(0.0, 1.0)))
    }
}

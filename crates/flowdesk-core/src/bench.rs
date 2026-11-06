//! Loopback harness: real sockets + real encryption, mock input devices.
//! Used by `flowdesk bench` and the integration tests. Numbers it produces measure the
//! software path only (no physical network, no OS input stack).

use crate::backend::{AllowAll, Injector, RawEvent};
use crate::client::{start_client, ClientConfig};
use crate::host::Host;
use crate::identity::{Identity, TrustStore};
use crate::stats::{LatencyStats, Summary};
use anyhow::{bail, Result};
use rdev::{Button, Key};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Report {
    pub ping_rtt: Summary,
    pub input_latency: Summary,
    pub probes: usize,
}

struct ProbeInjector {
    x: Arc<AtomicI64>,
    keys: Arc<Mutex<Vec<(Key, bool)>>>,
}

impl Injector for ProbeInjector {
    fn mouse_abs(&mut self, x: f64, _y: f64) {
        self.x.store(x as i64, Ordering::SeqCst);
    }
    fn button(&mut self, _: Button, _: bool) {}
    fn wheel(&mut self, _: i64, _: i64) {}
    fn key(&mut self, k: Key, d: bool) {
        self.keys.lock().unwrap().push((k, d));
    }
    fn screen_size(&self) -> (f64, f64) {
        (1920.0, 1080.0)
    }
}

fn wait_for(cond: impl Fn() -> bool, timeout: Duration) -> bool {
    let t = Instant::now();
    while t.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::hint::spin_loop();
    }
    cond()
}

/// `pings`: number of ping/pong round trips. `probes`: number of mouse-motion probes
/// (host event -> client injector call, measured with one clock in one process).
pub fn run_loopback(pings: usize, probes: usize) -> Result<Report> {
    let (etx, _erx) = channel();
    let host_id = Identity::generate()?;
    let cli_id = Identity::generate()?;
    let warp_log = Arc::new(Mutex::new(Vec::new()));
    let wl = warp_log.clone();
    let host = Host::new(
        "bench-host".into(),
        host_id,
        Arc::new(Mutex::new(TrustStore::in_memory())),
        Arc::new(AllowAll),
        (1920.0, 1080.0),
        Arc::new(move |x, y| wl.lock().unwrap().push((x, y))),
        etx.clone(),
        HashMap::new(),
    );
    let addr = host.listen("127.0.0.1:0")?;
    let x = Arc::new(AtomicI64::new(-1));
    let keys = Arc::new(Mutex::new(Vec::new()));
    let handle = start_client(
        ClientConfig { host: addr.to_string(), name: "bench-client".into() },
        cli_id,
        Arc::new(Mutex::new(TrustStore::in_memory())),
        Arc::new(AllowAll),
        Box::new(ProbeInjector { x: x.clone(), keys }),
        etx,
    );
    let h2 = host.clone();
    if !wait_for(move || !h2.peers().is_empty(), Duration::from_secs(5)) {
        bail!("client did not connect");
    }

    for _ in 0..pings {
        host.ping_now();
        std::thread::sleep(Duration::from_millis(2));
    }
    std::thread::sleep(Duration::from_millis(100));
    let peers = host.peers();
    let ping_rtt = peers[0].rtt;

    // Hand control to the client by pushing the cursor into the right edge.
    host.on_raw(RawEvent::Move { x: 1919.0, y: 540.0 });
    let xs = x.clone();
    if !wait_for(move || xs.load(Ordering::SeqCst) == 1, Duration::from_secs(2)) {
        bail!("client never received Enter");
    }
    host.on_raw(RawEvent::Move { x: 960.0, y: 540.0 }); // landing of the re-centre warp
    let mut stats = LatencyStats::default();
    for k in 1..=probes as i64 {
        let t = Instant::now();
        host.on_raw(RawEvent::Move { x: 961.0, y: 540.0 });
        let (xs, target) = (x.clone(), 1 + k);
        if !wait_for(move || xs.load(Ordering::SeqCst) == target, Duration::from_secs(2)) {
            bail!("probe {k} lost");
        }
        stats.record(t.elapsed().as_micros() as u64);
        std::thread::sleep(Duration::from_micros(300));
    }
    host.return_control();
    handle.stop();
    host.shutdown();
    Ok(Report { ping_rtt, input_latency: stats.summary(), probes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_end_to_end() {
        let r = run_loopback(50, 200).unwrap();
        println!(
            "loopback ping p50={}us p95={}us | input p50={}us p95={}us p99={}us max={}us",
            r.ping_rtt.p50_us, r.ping_rtt.p95_us, r.input_latency.p50_us,
            r.input_latency.p95_us, r.input_latency.p99_us, r.input_latency.max_us
        );
        assert!(r.ping_rtt.count >= 40);
        assert_eq!(r.input_latency.count, 200);
        // Generous bound so a loaded CI runner doesn't flake; real figures are far lower.
        assert!(r.input_latency.p50_us < 20_000);
    }

    #[test]
    fn untrusted_client_is_refused_when_verifier_denies() {
        use crate::backend::DenyAll;
        let (etx, _erx) = channel();
        let host = Host::new(
            "h".into(),
            Identity::generate().unwrap(),
            Arc::new(Mutex::new(TrustStore::in_memory())),
            Arc::new(DenyAll),
            (1920.0, 1080.0),
            Arc::new(|_, _| {}),
            etx.clone(),
            HashMap::new(),
        );
        let addr = host.listen("127.0.0.1:0").unwrap();
        let h = start_client(
            ClientConfig { host: addr.to_string(), name: "evil".into() },
            Identity::generate().unwrap(),
            Arc::new(Mutex::new(TrustStore::in_memory())),
            Arc::new(AllowAll),
            Box::new(ProbeInjector { x: Arc::new(AtomicI64::new(0)), keys: Arc::new(Mutex::new(vec![])) }),
            etx,
        );
        std::thread::sleep(Duration::from_millis(800));
        assert!(host.peers().is_empty());
        // Even forced edge hits cannot route input to a peer that never authenticated.
        assert!(!host.on_raw(RawEvent::Move { x: 1919.0, y: 5.0 }));
        assert!(!host.is_remote());
        h.stop();
        host.shutdown();
    }

    #[test]
    fn hotkey_returns_control() {
        let (etx, _erx) = channel();
        let host = Host::new(
            "h".into(),
            Identity::generate().unwrap(),
            Arc::new(Mutex::new(TrustStore::in_memory())),
            Arc::new(AllowAll),
            (1920.0, 1080.0),
            Arc::new(|_, _| {}),
            etx.clone(),
            HashMap::new(),
        );
        let addr = host.listen("127.0.0.1:0").unwrap();
        let h = start_client(
            ClientConfig { host: addr.to_string(), name: "c".into() },
            Identity::generate().unwrap(),
            Arc::new(Mutex::new(TrustStore::in_memory())),
            Arc::new(AllowAll),
            Box::new(ProbeInjector { x: Arc::new(AtomicI64::new(0)), keys: Arc::new(Mutex::new(vec![])) }),
            etx,
        );
        let h2 = host.clone();
        assert!(wait_for(move || !h2.peers().is_empty(), Duration::from_secs(5)));
        assert!(host.on_raw(RawEvent::Move { x: 1919.0, y: 5.0 }) == false);
        assert!(host.is_remote());
        host.on_raw(RawEvent::Key { key: Key::ControlLeft, down: true });
        host.on_raw(RawEvent::Key { key: Key::Alt, down: true });
        assert!(host.on_raw(RawEvent::Key { key: Key::Pause, down: true }));
        assert!(!host.is_remote());
        h.stop();
        host.shutdown();
    }
}

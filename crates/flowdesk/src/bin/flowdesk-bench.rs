//! Console tool: measures the software path over loopback (real sockets + encryption,
//! mock input devices). It does NOT measure real networks, VPNs, or OS input stacks.

fn main() -> anyhow::Result<()> {
    let probes: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
    println!("Flowdesk loopback benchmark ({probes} probes, 200 pings) ...");
    let r = flowdesk_core::bench::run_loopback(200, probes)?;
    let line = |n: &str, s: flowdesk_core::stats::Summary| {
        println!(
            "{n:<34} min {:>6}us  p50 {:>6}us  p95 {:>6}us  p99 {:>6}us  max {:>6}us",
            s.min_us, s.p50_us, s.p95_us, s.p99_us, s.max_us
        )
    };
    line("ping round trip (encrypted TCP)", r.ping_rtt);
    line("mouse event -> client injector", r.input_latency);
    println!("Software path only; real-world latency depends on your network and OS.");
    Ok(())
}

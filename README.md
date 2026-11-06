# Flowdesk

Share one keyboard and mouse between Windows and Linux computers — an open-source (MIT), encrypted, low-overhead alternative to Mouse Without Borders / Synergy-style tools, written in Rust with a native GUI (egui).

> **Status: early (v0.1).** Core protocol, security, edge-switching logic and GUI are implemented and tested on loopback with mock input devices. It has **not** been tested on two real machines, over a real VPN, on real Linux hardware, or on Wayland. See [What was tested](#what-was-tested) and [Limitations](#limitations). It will not work "in any condition" — nothing like this can.

## How it works

- **Host** (the PC with the physical keyboard/mouse) listens on a TCP port. **Clients** connect to it by `host:port` — type the LAN or VPN (Tailscale / WireGuard / OpenVPN) address. There is no broadcast discovery and no network scanning, so routed/VPN networks work the same as LAN.
- Push the pointer into the screen edge where you placed a client (Screen layout page) and the host swallows local input and streams it to that client; push back through the entry edge to return. **Ctrl+Alt+Pause** or the *Return control* button always returns control immediately, and a dropped connection returns control automatically.
- Mouse motion is sent as relative deltas. If the network is slow, queued motion is merged (coalesced) before sending, so delay never accumulates into "rubber-band" lag. Messages are tiny (a mouse move is ~6 bytes before encryption), TCP_NODELAY is on, and each side sends keep-alives (0.5 s) with a 6 s dead-peer timeout and automatic reconnect with back-off.
- **Diagnostics** page: live round-trip time of the encrypted keep-alive pings (last / median / 95th / 99th / max + graph) per client.

### Security

- Noise `XX_25519_ChaChaPoly_BLAKE2s` handshake (via the `snow` crate): mutual authentication with long-term keys and forward-secret session keys; all traffic is encrypted and integrity-protected.
- **Pairing**: the first time an unknown computer connects, *both* sides show its key fingerprint (e.g. `ab12-cd34-…`) and require you to confirm they match. Trusted fingerprints are stored in `trusted.json` (config dir) and can be revoked in the Security page. Unverified peers can never send or receive input.
- No telemetry, no update checks, no outbound connections except the one you configure. Identity key is stored in your user config dir (`identity.key`, mode 0600 on Linux).
- Host side limits concurrent not-yet-authenticated connections. Not audited — treat as unreviewed software and keep the port on a VPN/trusted network.

## Install / run

Download from the [Releases](https://github.com/itsnavin/flowdesk/releases) page (Windows `.zip`, Linux `.tar.gz`), or build:

```
cargo build --release          # binaries: target/release/flowdesk, flowdesk-bench
cargo test --workspace
cargo run --release --bin flowdesk-bench -- 1000   # loopback latency measurement
```

Linux build deps: `libx11-dev libxtst-dev libxi-dev libevdev-dev libudev-dev libxkbcommon-dev libwayland-dev pkg-config`. Linux *host* capture needs read/write access to `/dev/input` (add your user to the `input` group) and an X11 session.

Quick start: on the host choose *This PC shares…* → *Start sharing*; on the client choose *receives input…* → enter `host-ip:24880` → *Connect*; verify the fingerprint on both screens; place the client on the Screen layout page. Open TCP 24880 in the host firewall.

## What was tested

Automated (`cargo test --workspace`, run on Windows locally and on Windows + Ubuntu in CI):

- Protocol encode/decode, motion coalescing, malformed input.
- Noise handshake + encrypted framing over real localhost sockets; tampered frames rejected.
- Identity persistence, fingerprints, trust store.
- Client state machine (virtual cursor, edge hand-back, stuck-key release) with a mock injector.
- Integration over 127.0.0.1 with real sockets/encryption and mock devices: connect, pairing refusal, edge hand-over, hotkey returning control, input delivery.

Loopback latency (`flowdesk-bench`, Windows, release build, one run on a development PC, noisy because of OS scheduling): ping round trip p50 ≈ 0.9 ms (p95 ≈ 4 ms); host event → client injector call p50 ≈ 0.4 ms (p95 ≈ 1.9 ms). This measures **only the software path on one machine**. On GitHub-hosted CI runners (500 probes): Linux ping p50 ≈ 23 µs, host event → client injector p50 ≈ 16 µs, p99 ≈ 25 µs; Windows ping p50 ≈ 81 µs, event → injector p50 ≈ 45 µs, p99 ≈ 105 µs. It says nothing about your network, VPN, or the OS input stack; real latency is dominated by the link RTT, which the Diagnostics page shows you.

Also: the Windows GUI was launched and stayed running (no screenshot-based UI review). **Not tested:** two physical machines, real VPNs, real key/mouse injection and capture end-to-end, Linux GUI/capture/injection at runtime (builds in CI only), Wayland, high-DPI/multi-monitor, Windows UAC cases.

## Limitations

- **Windows**: cannot control elevated (admin) windows, UAC secure desktop, lock or login screen from a non-elevated, non-service process. Primary monitor only; DPI scaling and multi-monitor setups are untested.
- **Linux**: capture and injection go through `rdev` (X11 + evdev). **Wayland sessions are not supported**; proper support needs libei / the RemoteDesktop portal / uinput and is future work. Linux host capture is experimental and untested on real hardware.
- TCP over a lossy VPN can stall briefly (head-of-line blocking); a UDP transport is a possible future improvement.
- Clipboard sharing, file transfer, drag-and-drop between machines, macOS, and multi-client chains are not implemented.
- Keys are forwarded by key identity (rdev `Key`), so differing keyboard layouts between machines may produce different characters.
- Windows SmartScreen will warn about unsigned binaries.

## Research notes on existing free tools

Written from general knowledge of these projects (not re-verified against current docs for every detail — check upstream before relying on specifics); no code from them is used here, which is why Flowdesk is MIT.

| Tool | License | Architecture / notes |
|---|---|---|
| **Mouse Without Borders** (Microsoft PowerToys) | MIT | Windows only. Peer-to-peer over TCP with a shared security key and AES encryption; machines found via LAN or manually entered IPs. Strong Windows integration (clipboard/file drag, UAC handling via service). Reported issues include stutter/lag on busy or Wi-Fi networks and reconnect problems after sleep or VPN changes. |
| **Input Leap** | GPL-2.0 | Barrier fork; C++/Qt; X11 and macOS/Windows, Wayland support via libei is partial/experimental. Server/client model, TLS. |
| **Barrier** | GPL-2.0 | Fork of Synergy 1.9; largely unmaintained; server/client over TCP (24800) with optional SSL. |
| **Deskflow** | GPL-2.0 (with OpenSSL exception) | Upstream open-source core of Synergy; C++/Qt; active Wayland work through libei and XDG portals. |

Lessons applied: avoid depending on LAN discovery (manual `host:port` first-class); keep messages tiny and disable Nagle; coalesce motion instead of queueing it; explicit key-fingerprint verification instead of a shared password only; emergency hotkey; document Wayland/UAC limits instead of hiding them. Likely lag causes in this class of tools (unverified here): Wi-Fi power-save/jitter, TCP delay and queued backlogs, VPN MTU/fragmentation, and hooks that block the input thread while writing to the network — Flowdesk hands events to a separate sender thread so the OS input hook never waits on the network.

## Layout

```
crates/flowdesk-core   protocol, Noise transport, trust store, host/client logic, native input (rdev), loopback bench
crates/flowdesk        egui GUI (flowdesk) and the benchmark CLI (flowdesk-bench)
.github/workflows      CI: test + build Windows/Linux, publish release on v* tags
```

License: MIT.

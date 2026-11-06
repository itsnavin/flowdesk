#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use eframe::egui::{self, Align2, Color32, CornerRadius, FontId, RichText, Stroke, StrokeKind};
use flowdesk_core::backend::{Event, Verifier};
use flowdesk_core::client::{start_client, ClientConfig, ClientHandle};
use flowdesk_core::host::{Host, PeerInfo};
use flowdesk_core::identity::{config_dir, Identity, TrustStore};
use flowdesk_core::native::{self, HostSlot, NativeInjector};
use flowdesk_core::proto::Side;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ACCENT: Color32 = Color32::from_rgb(0x4c, 0x8d, 0xff);
const GOOD: Color32 = Color32::from_rgb(0x3d, 0xd6, 0x8c);
const WARN: Color32 = Color32::from_rgb(0xf5, 0xa6, 0x23);
const BAD: Color32 = Color32::from_rgb(0xff, 0x5c, 0x6c);
const CARD: Color32 = Color32::from_rgb(0x1c, 0x21, 0x2b);
const BG: Color32 = Color32::from_rgb(0x12, 0x15, 0x1c);
const MUTED: Color32 = Color32::from_rgb(0x8a, 0x93, 0xa6);

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    name: String,
    listen: String,
    connect_to: String,
    layout: HashMap<String, Side>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            name: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "my-computer".into()),
            listen: "0.0.0.0:24880".into(),
            connect_to: String::new(),
            layout: HashMap::new(),
        }
    }
}

impl Settings {
    fn load() -> Self {
        std::fs::read_to_string(config_dir().join("settings.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }
    fn save(&self) {
        let _ = std::fs::create_dir_all(config_dir());
        if let Ok(t) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(config_dir().join("settings.json"), t);
        }
    }
}

/// Asks the user (via the GUI) whether to trust an unknown peer; blocks the network thread.
struct PendingTrust {
    fingerprint: String,
    addr: String,
    decision: Option<bool>,
}

struct GuiVerifier {
    pending: Arc<Mutex<Vec<PendingTrust>>>,
    ctx: egui::Context,
}

impl Verifier for GuiVerifier {
    fn confirm(&self, fingerprint: &str, addr: &str) -> bool {
        self.pending.lock().unwrap().push(PendingTrust {
            fingerprint: fingerprint.into(),
            addr: addr.into(),
            decision: None,
        });
        self.ctx.request_repaint();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(90) {
            std::thread::sleep(Duration::from_millis(100));
            let mut p = self.pending.lock().unwrap();
            if let Some(i) = p.iter().position(|r| r.fingerprint == fingerprint && r.decision.is_some()) {
                return p.remove(i).decision.unwrap();
            }
        }
        self.pending.lock().unwrap().retain(|r| r.fingerprint != fingerprint);
        false
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Page {
    Connect,
    Layout,
    Diagnostics,
    Security,
    About,
}

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Host,
    Client,
}

struct App {
    page: Page,
    mode: Mode,
    settings: Settings,
    identity: Identity,
    trust: Arc<Mutex<TrustStore>>,
    verifier: Arc<GuiVerifier>,
    pending: Arc<Mutex<Vec<PendingTrust>>>,
    events_tx: Sender<Event>,
    events_rx: Receiver<Event>,
    log: Vec<String>,
    host: Option<Arc<Host>>,
    host_slot: HostSlot,
    capture_started: bool,
    capture_error: Option<String>,
    client: Option<ClientHandle>,
    connected_to: Option<String>,
    controlling: Option<String>,
    status: String,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut v = egui::Visuals::dark();
        v.panel_fill = BG;
        v.window_fill = CARD;
        v.widgets.noninteractive.bg_fill = CARD;
        v.selection.bg_fill = ACCENT;
        v.widgets.inactive.corner_radius = CornerRadius::same(6);
        v.widgets.hovered.corner_radius = CornerRadius::same(6);
        v.widgets.active.corner_radius = CornerRadius::same(6);
        cc.egui_ctx.set_visuals(v);
        cc.egui_ctx.style_mut(|s| {
            s.spacing.item_spacing = egui::vec2(10.0, 10.0);
            s.spacing.button_padding = egui::vec2(14.0, 8.0);
        });
        let dir = config_dir();
        let identity = Identity::load_or_create(&dir).expect("cannot create identity");
        let trust = Arc::new(Mutex::new(TrustStore::load(&dir)));
        let pending = Arc::new(Mutex::new(Vec::new()));
        let (events_tx, events_rx) = channel();
        let settings = Settings::load();
        App {
            page: Page::Connect,
            mode: Mode::Host,
            verifier: Arc::new(GuiVerifier { pending: pending.clone(), ctx: cc.egui_ctx.clone() }),
            pending,
            settings,
            identity,
            trust,
            events_tx,
            events_rx,
            log: vec![],
            host: None,
            host_slot: Arc::new(Mutex::new(None)),
            capture_started: false,
            capture_error: None,
            client: None,
            connected_to: None,
            controlling: None,
            status: "Idle".into(),
        }
    }

    fn drain_events(&mut self) {
        while let Ok(ev) = self.events_rx.try_recv() {
            match ev {
                Event::Log(s) => self.push_log(s),
                Event::PeerConnected { name, .. } => {
                    self.connected_to = Some(name.clone());
                    self.push_log(format!("Connected: {name}"));
                }
                Event::PeerDisconnected { name } => {
                    if self.mode == Mode::Client {
                        self.connected_to = None;
                    }
                    self.push_log(format!("Disconnected: {name}"));
                }
                Event::Control(c) => self.controlling = c,
                Event::Rtt { .. } => {}
            }
        }
    }

    fn push_log(&mut self, s: String) {
        self.log.push(s);
        if self.log.len() > 200 {
            self.log.remove(0);
        }
    }

    fn start_host(&mut self) {
        let screen = native::screen_size();
        let host = Host::new(
            self.settings.name.clone(),
            self.identity.clone(),
            self.trust.clone(),
            self.verifier.clone(),
            screen,
            native::native_warp(),
            self.events_tx.clone(),
            self.settings.layout.clone(),
        );
        match host.listen(&self.settings.listen) {
            Ok(_) => {
                *self.host_slot.lock().unwrap() = Some(host.clone());
                self.host = Some(host);
                self.status = format!("Hosting on {}", self.settings.listen);
                if !self.capture_started {
                    self.capture_started = true;
                    let slot = self.host_slot.clone();
                    let tx = self.events_tx.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = native::capture(slot) {
                            let _ = tx.send(Event::Log(format!(
                                "Input capture failed: {e} (Linux: add your user to the 'input' group; Wayland is not supported)"
                            )));
                        }
                    });
                }
            }
            Err(e) => self.push_log(format!("Cannot listen on {}: {e:#}", self.settings.listen)),
        }
    }

    fn stop_host(&mut self) {
        *self.host_slot.lock().unwrap() = None;
        if let Some(h) = self.host.take() {
            h.shutdown();
        }
        self.controlling = None;
        self.status = "Idle".into();
    }

    fn start_client(&mut self) {
        let h = start_client(
            ClientConfig { host: self.settings.connect_to.clone(), name: self.settings.name.clone() },
            self.identity.clone(),
            self.trust.clone(),
            self.verifier.clone(),
            Box::new(NativeInjector),
            self.events_tx.clone(),
        );
        self.client = Some(h);
        self.status = format!("Connecting to {}", self.settings.connect_to);
    }

    fn stop_client(&mut self) {
        if let Some(c) = self.client.take() {
            c.stop();
        }
        self.connected_to = None;
        self.controlling = None;
        self.status = "Idle".into();
    }

    fn running(&self) -> bool {
        self.host.is_some() || self.client.is_some()
    }
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(CARD)
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::same(16))
        .stroke(Stroke::new(1.0, Color32::from_rgb(0x2a, 0x31, 0x3f)))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        });
}

fn heading(ui: &mut egui::Ui, t: &str) {
    ui.label(RichText::new(t).size(24.0).strong());
}

fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    ui.label(RichText::new(format!("  {text}  ")).color(Color32::BLACK).background_color(color).strong());
}

fn big_button(ui: &mut egui::Ui, text: &str, color: Color32) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).size(16.0).strong().color(Color32::WHITE))
            .fill(color)
            .min_size(egui::vec2(180.0, 38.0)),
    )
}

fn us(v: u64) -> String {
    if v >= 1000 {
        format!("{:.2} ms", v as f64 / 1000.0)
    } else {
        format!("{v} µs")
    }
}

fn side_name(s: Option<Side>) -> &'static str {
    match s {
        None => "Not placed",
        Some(Side::Left) => "Left of this PC",
        Some(Side::Right) => "Right of this PC",
        Some(Side::Top) => "Above this PC",
        Some(Side::Bottom) => "Below this PC",
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.drain_events();
        ctx.request_repaint_after(Duration::from_millis(250));

        let mut decision: Option<(String, bool)> = None;
        {
            let pend = self.pending.lock().unwrap();
            if let Some(p) = pend.iter().find(|p| p.decision.is_none()) {
                egui::Window::new("Trust this computer?")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(format!("A computer at {} wants to connect.", p.addr));
                        ui.label("Check that this fingerprint is shown on the other computer too:");
                        ui.label(RichText::new(&p.fingerprint).monospace().size(22.0).color(ACCENT));
                        ui.label(RichText::new("Only accept if the fingerprints match exactly.").color(WARN));
                        ui.horizontal(|ui| {
                            if big_button(ui, "Trust & connect", GOOD).clicked() {
                                decision = Some((p.fingerprint.clone(), true));
                            }
                            if big_button(ui, "Reject", BAD).clicked() {
                                decision = Some((p.fingerprint.clone(), false));
                            }
                        });
                    });
            }
        }
        if let Some((fp, ok)) = decision {
            if let Some(p) = self.pending.lock().unwrap().iter_mut().find(|p| p.fingerprint == fp) {
                p.decision = Some(ok);
            }
        }

        egui::SidePanel::left("nav").exact_width(190.0).show(ctx, |ui| {
            ui.add_space(8.0);
            ui.label(RichText::new("Flowdesk").size(26.0).strong().color(ACCENT));
            ui.label(RichText::new("one keyboard, many PCs").color(MUTED));
            ui.add_space(14.0);
            for (p, label) in [
                (Page::Connect, "Connect"),
                (Page::Layout, "Screen layout"),
                (Page::Diagnostics, "Diagnostics"),
                (Page::Security, "Security"),
                (Page::About, "About & limits"),
            ] {
                if ui
                    .add_sized([170.0, 34.0], egui::SelectableLabel::new(self.page == p, RichText::new(label).size(15.0)))
                    .clicked()
                {
                    self.page = p;
                }
            }
            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.add_space(8.0);
                if self.host.as_ref().map(|h| h.is_remote()).unwrap_or(false)
                    && big_button(ui, "Return control", BAD).clicked()
                {
                    if let Some(h) = &self.host {
                        h.return_control();
                    }
                }
                ui.label(RichText::new("Panic key: Ctrl+Alt+Pause").color(MUTED).small());
            });
        });

        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin::same(20))).show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.page {
                Page::Connect => self.page_connect(ui),
                Page::Layout => self.page_layout(ui),
                Page::Diagnostics => self.page_diag(ui),
                Page::Security => self.page_security(ui),
                Page::About => page_about(ui),
            });
        });
    }
}

impl App {
    fn page_connect(&mut self, ui: &mut egui::Ui) {
        heading(ui, "Connect");
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("This computer's name");
                ui.add_enabled(!self.running(), egui::TextEdit::singleline(&mut self.settings.name).desired_width(220.0));
                ui.separator();
                let (txt, col) = if self.controlling.is_some() {
                    (format!("Controlling: {}", self.controlling.clone().unwrap()), ACCENT)
                } else if self.connected_to.is_some() || self.host.as_ref().map(|h| !h.peers().is_empty()).unwrap_or(false) {
                    ("Connected".to_string(), GOOD)
                } else if self.running() {
                    (self.status.clone(), WARN)
                } else {
                    ("Stopped".to_string(), MUTED)
                };
                pill(ui, &txt, col);
            });
        });
        card(ui, |ui| {
            ui.add_enabled_ui(!self.running(), |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.mode, Mode::Host, RichText::new("This PC shares its keyboard & mouse").size(15.0));
                    ui.selectable_value(&mut self.mode, Mode::Client, RichText::new("This PC receives input from another PC").size(15.0));
                });
            });
            ui.separator();
            match self.mode {
                Mode::Host => {
                    ui.label("Listen address (works over LAN and VPN — use the VPN interface IP or 0.0.0.0):");
                    ui.add_enabled(!self.running(), egui::TextEdit::singleline(&mut self.settings.listen).desired_width(260.0));
                    ui.label(RichText::new("Open this TCP port in the firewall of the host. Nothing is broadcast or scanned.").color(MUTED));
                    if self.host.is_none() {
                        if big_button(ui, "Start sharing", ACCENT).clicked() {
                            self.settings.save();
                            self.start_host();
                        }
                    } else if big_button(ui, "Stop sharing", BAD).clicked() {
                        self.stop_host();
                    }
                    if let Some(h) = &self.host {
                        ui.add_space(6.0);
                        ui.label(RichText::new("Connected computers").strong());
                        let peers = h.peers();
                        if peers.is_empty() {
                            ui.label(RichText::new("Waiting for clients to connect…").color(MUTED));
                        }
                        for p in peers {
                            ui.horizontal(|ui| {
                                pill(ui, "online", GOOD);
                                ui.label(format!("{} — {} — RTT {}", p.name, side_name(p.side), us(p.rtt.last_us)));
                            });
                        }
                    }
                }
                Mode::Client => {
                    ui.label("Host address (IP or hostname : port — a VPN/Tailscale/WireGuard IP works):");
                    ui.add_enabled(
                        !self.running(),
                        egui::TextEdit::singleline(&mut self.settings.connect_to).hint_text("100.64.0.10:24880").desired_width(260.0),
                    );
                    if self.client.is_none() {
                        if big_button(ui, "Connect", ACCENT).clicked() && !self.settings.connect_to.trim().is_empty() {
                            self.settings.save();
                            self.start_client();
                        }
                    } else if big_button(ui, "Disconnect", BAD).clicked() {
                        self.stop_client();
                    }
                    ui.label(RichText::new("Reconnects automatically with back-off if the link drops.").color(MUTED));
                }
            }
        });
        if let Some(e) = &self.capture_error {
            ui.colored_label(BAD, e);
        }
        card(ui, |ui| {
            ui.label(RichText::new("Activity").strong());
            egui::ScrollArea::vertical().max_height(180.0).stick_to_bottom(true).show(ui, |ui| {
                for l in &self.log {
                    ui.label(RichText::new(l).monospace().small().color(MUTED));
                }
            });
        });
    }

    fn page_layout(&mut self, ui: &mut egui::Ui) {
        heading(ui, "Screen layout");
        let Some(host) = self.host.clone() else {
            ui.label(RichText::new("Start sharing on the Connect page to arrange connected computers.").color(MUTED));
            return;
        };
        let peers = host.peers();
        card(ui, |ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 260.0), egui::Sense::hover());
            let p = ui.painter_at(rect);
            let c = rect.center();
            let me = egui::Rect::from_center_size(c, egui::vec2(160.0, 100.0));
            let slot = |s: Side| match s {
                Side::Left => egui::Rect::from_center_size(c + egui::vec2(-190.0, 0.0), egui::vec2(160.0, 100.0)),
                Side::Right => egui::Rect::from_center_size(c + egui::vec2(190.0, 0.0), egui::vec2(160.0, 100.0)),
                Side::Top => egui::Rect::from_center_size(c + egui::vec2(0.0, -115.0), egui::vec2(160.0, 60.0)),
                Side::Bottom => egui::Rect::from_center_size(c + egui::vec2(0.0, 115.0), egui::vec2(160.0, 60.0)),
            };
            for s in Side::ALL {
                let r = slot(s);
                let occupant = peers.iter().find(|x| x.side == Some(s));
                let col = if occupant.is_some() { ACCENT } else { Color32::from_rgb(0x2a, 0x31, 0x3f) };
                p.rect_filled(r, 8, if occupant.is_some() { Color32::from_rgb(0x1f, 0x3a, 0x6b) } else { BG });
                p.rect_stroke(r, 8, Stroke::new(1.5, col), StrokeKind::Inside);
                p.text(
                    r.center(),
                    Align2::CENTER_CENTER,
                    occupant.map(|o| o.name.as_str()).unwrap_or("empty"),
                    FontId::proportional(15.0),
                    if occupant.is_some() { Color32::WHITE } else { MUTED },
                );
            }
            p.rect_filled(me, 8, Color32::from_rgb(0x26, 0x2d, 0x3b));
            p.rect_stroke(me, 8, Stroke::new(2.0, GOOD), StrokeKind::Inside);
            p.text(me.center(), Align2::CENTER_CENTER, "This computer", FontId::proportional(16.0), Color32::WHITE);
        });
        card(ui, |ui| {
            if peers.is_empty() {
                ui.label(RichText::new("No computers connected yet.").color(MUTED));
            }
            let mut changed = false;
            for p in &peers {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&p.name).strong());
                    let mut sel = p.side;
                    egui::ComboBox::from_id_salt(&p.fingerprint)
                        .selected_text(side_name(sel))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut sel, None, side_name(None));
                            for s in Side::ALL {
                                ui.selectable_value(&mut sel, Some(s), side_name(Some(s)));
                            }
                        });
                    if sel != p.side {
                        host.set_side(&p.fingerprint, sel);
                        changed = true;
                    }
                });
            }
            if changed {
                self.settings.layout = host.layout();
                self.settings.save();
            }
            ui.label(RichText::new("Move the pointer into the matching edge of this screen to hand over control.").color(MUTED));
        });
    }

    fn page_diag(&mut self, ui: &mut egui::Ui) {
        heading(ui, "Diagnostics");
        ui.label(RichText::new("Round-trip time of encrypted keep-alive pings (a ping every 0.5 s). This is the link's floor; input follows the same path.").color(MUTED));
        let peers: Vec<PeerInfo> = self.host.as_ref().map(|h| h.peers()).unwrap_or_default();
        if peers.is_empty() {
            card(ui, |ui| {
                ui.label(if self.mode == Mode::Client {
                    "Latency graphs are shown on the host. A client logs connection events on the Connect page."
                } else {
                    "No connected computers."
                });
            });
        }
        for p in peers {
            card(ui, |ui| {
                ui.label(RichText::new(&p.name).strong().size(18.0));
                let r = p.rtt;
                ui.horizontal_wrapped(|ui| {
                    for (k, v) in [
                        ("last", r.last_us),
                        ("median", r.p50_us),
                        ("95th", r.p95_us),
                        ("99th", r.p99_us),
                        ("max", r.max_us),
                    ] {
                        ui.vertical(|ui| {
                            ui.label(RichText::new(k).color(MUTED).small());
                            let col = if v < 20_000 { GOOD } else if v < 80_000 { WARN } else { BAD };
                            ui.label(RichText::new(us(v)).size(20.0).strong().color(col));
                        });
                        ui.add_space(14.0);
                    }
                });
                if let Some(h) = &self.host {
                    let hist = h.rtt_history(p.id);
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 120.0), egui::Sense::hover());
                    let pt = ui.painter_at(rect);
                    pt.rect_filled(rect, 6, BG);
                    if hist.len() > 1 {
                        let maxv = (*hist.iter().max().unwrap()).max(1000) as f32;
                        let n = hist.len() as f32 - 1.0;
                        let pts: Vec<egui::Pos2> = hist
                            .iter()
                            .enumerate()
                            .map(|(i, v)| {
                                egui::pos2(
                                    rect.left() + rect.width() * i as f32 / n,
                                    rect.bottom() - 6.0 - (rect.height() - 12.0) * (*v as f32 / maxv),
                                )
                            })
                            .collect();
                        pt.add(egui::Shape::line(pts, Stroke::new(1.8, ACCENT)));
                        pt.text(rect.left_top() + egui::vec2(6.0, 4.0), Align2::LEFT_TOP, format!("scale 0–{}", us(maxv as u64)), FontId::proportional(11.0), MUTED);
                    }
                }
            });
        }
    }

    fn page_security(&mut self, ui: &mut egui::Ui) {
        heading(ui, "Security");
        card(ui, |ui| {
            ui.label(RichText::new("Your fingerprint").strong());
            ui.label(RichText::new(self.identity.fingerprint()).monospace().size(22.0).color(ACCENT));
            ui.label(RichText::new("Compare this with what the other computer shows when it asks you to trust a connection. Connections use Noise_XX (X25519, ChaCha20-Poly1305); no input is accepted from an unverified peer.").color(MUTED));
        });
        card(ui, |ui| {
            ui.label(RichText::new("Trusted computers").strong());
            let peers: Vec<(String, String)> =
                self.trust.lock().unwrap().peers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            if peers.is_empty() {
                ui.label(RichText::new("None yet.").color(MUTED));
            }
            for (fp, name) in peers {
                ui.horizontal(|ui| {
                    ui.label(format!("{name}  "));
                    ui.label(RichText::new(&fp).monospace().color(MUTED));
                    if ui.button("Forget").clicked() {
                        self.trust.lock().unwrap().forget(&fp);
                    }
                });
            }
        });
    }
}

fn page_about(ui: &mut egui::Ui) {
    heading(ui, "About & limits");
    card(ui, |ui| {
        ui.label(format!("Flowdesk {} — MIT licensed, no telemetry, no network scanning.", env!("CARGO_PKG_VERSION")));
        ui.label(RichText::new("Known limits").strong());
        for t in [
            "Windows: cannot control elevated (admin) windows, UAC prompts, the lock or login screen unless Flowdesk itself runs there.",
            "Linux host: needs access to /dev/input (input group) and an X11 session; Wayland sessions are not supported yet.",
            "Linux client: injection works under X11 only.",
            "Primary monitor only; clipboard sharing is not implemented.",
            "TCP over a lossy VPN can add delay (head-of-line blocking); motion is coalesced so it never queues up.",
            "Panic key: Ctrl+Alt+Pause, or the Return control button, gives input back immediately.",
        ] {
            ui.label(format!("•  {t}"));
        }
    });
}

fn main() -> eframe::Result {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Flowdesk")
            .with_inner_size([980.0, 680.0])
            .with_min_inner_size([780.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native("Flowdesk", opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

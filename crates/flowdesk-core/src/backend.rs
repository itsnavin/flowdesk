//! Platform abstraction for capturing and injecting input.

use rdev::{Button, Key};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq)]
pub enum RawEvent {
    /// Absolute pointer position in physical pixels.
    Move { x: f64, y: f64 },
    Button { button: Button, down: bool },
    Wheel { dx: i64, dy: i64 },
    Key { key: Key, down: bool },
}

pub trait Injector: Send {
    fn mouse_abs(&mut self, x: f64, y: f64);
    fn button(&mut self, button: Button, down: bool);
    fn wheel(&mut self, dx: i64, dy: i64);
    fn key(&mut self, key: Key, down: bool);
    fn screen_size(&self) -> (f64, f64);
}

/// Moves the local cursor (used by the host to re-centre / return the pointer).
pub type Warp = Arc<dyn Fn(f64, f64) + Send + Sync>;

/// Result of the user being asked whether to trust an unknown peer.
pub trait Verifier: Send + Sync {
    /// Called for peers whose fingerprint is not in the trust store.
    fn confirm(&self, fingerprint: &str, addr: &str) -> bool;
}

pub struct AllowAll;
impl Verifier for AllowAll {
    fn confirm(&self, _: &str, _: &str) -> bool {
        true
    }
}

pub struct DenyAll;
impl Verifier for DenyAll {
    fn confirm(&self, _: &str, _: &str) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub enum Event {
    Log(String),
    PeerConnected { name: String, fingerprint: String },
    PeerDisconnected { name: String },
    /// Name of the peer currently controlled, or `None` when input is local.
    Control(Option<String>),
    Rtt { peer: String, us: u64 },
}

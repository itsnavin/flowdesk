//! Real keyboard/mouse capture and injection (Windows hooks / Linux X11+evdev) via `rdev`.

use crate::backend::{Injector, RawEvent, Warp};
use crate::host::Host;
use rdev::{Button, EventType, Key};
use std::sync::Arc;

pub fn screen_size() -> (f64, f64) {
    match rdev::display_size() {
        Ok((w, h)) if w > 0 && h > 0 => (w as f64, h as f64),
        _ => (1920.0, 1080.0),
    }
}

pub struct NativeInjector;

fn sim(e: EventType) {
    let _ = rdev::simulate(&e);
}

impl Injector for NativeInjector {
    fn mouse_abs(&mut self, x: f64, y: f64) {
        sim(EventType::MouseMove { x, y });
    }
    fn button(&mut self, b: Button, down: bool) {
        sim(if down { EventType::ButtonPress(b) } else { EventType::ButtonRelease(b) });
    }
    fn wheel(&mut self, dx: i64, dy: i64) {
        sim(EventType::Wheel { delta_x: dx, delta_y: dy });
    }
    fn key(&mut self, k: Key, down: bool) {
        sim(if down { EventType::KeyPress(k) } else { EventType::KeyRelease(k) });
    }
    fn screen_size(&self) -> (f64, f64) {
        screen_size()
    }
}

pub fn native_warp() -> Warp {
    Arc::new(|x, y| sim(EventType::MouseMove { x, y }))
}

/// Shared slot so the (never-returning) capture thread always talks to the *current* host.
pub type HostSlot = Arc<std::sync::Mutex<Option<Arc<Host>>>>;

/// Blocks the calling thread, feeding global input into the host and swallowing events
/// while a client has control. Returns an error string if capture cannot start
/// (e.g. missing /dev/input permissions on Linux).
pub fn capture(slot: HostSlot) -> Result<(), String> {
    rdev::grab(move |ev| {
        let raw = match ev.event_type {
            EventType::MouseMove { x, y } => Some(RawEvent::Move { x, y }),
            EventType::ButtonPress(b) => Some(RawEvent::Button { button: b, down: true }),
            EventType::ButtonRelease(b) => Some(RawEvent::Button { button: b, down: false }),
            EventType::Wheel { delta_x, delta_y } => Some(RawEvent::Wheel { dx: delta_x, dy: delta_y }),
            EventType::KeyPress(k) => Some(RawEvent::Key { key: k, down: true }),
            EventType::KeyRelease(k) => Some(RawEvent::Key { key: k, down: false }),
        };
        let host = slot.lock().unwrap().clone();
        match (raw, host) {
            (Some(r), Some(host)) => {
                if host.on_raw(r) {
                    None
                } else {
                    Some(ev)
                }
            }
            _ => Some(ev),
        }
    })
    .map_err(|e| format!("{e:?}"))
}

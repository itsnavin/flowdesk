//! Wire protocol: small postcard-encoded messages carried inside encrypted frames.

use rdev::{Button, Key};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Side {
    Left,
    Right,
    Top,
    Bottom,
}

impl Side {
    pub fn opposite(self) -> Side {
        match self {
            Side::Left => Side::Right,
            Side::Right => Side::Left,
            Side::Top => Side::Bottom,
            Side::Bottom => Side::Top,
        }
    }
    pub const ALL: [Side; 4] = [Side::Left, Side::Right, Side::Top, Side::Bottom];
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum InputEv {
    /// Relative pointer motion in physical pixels (coalesced).
    MouseRel { dx: i32, dy: i32 },
    Button { button: Button, down: bool },
    Wheel { dx: i64, dy: i64 },
    Key { key: Key, down: bool },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Msg {
    Hello { version: u16, name: String, width: u32, height: u32 },
    /// Host hands control to this client; `edge` is the client edge the cursor enters through,
    /// `frac` the position along that edge in 0..=1.
    Enter { edge: Side, frac: f32 },
    /// Client returns control to the host at fraction `frac` along the shared edge.
    Leave { frac: f32 },
    Input(InputEv),
    /// Release every key/button the client believes is pressed.
    ReleaseAll,
    Ping { id: u64, sent_us: u64 },
    Pong { id: u64, sent_us: u64 },
    Bye,
}

pub fn encode(msg: &Msg) -> anyhow::Result<Vec<u8>> {
    Ok(postcard::to_stdvec(msg)?)
}

pub fn decode(buf: &[u8]) -> anyhow::Result<Msg> {
    Ok(postcard::from_bytes(buf)?)
}

/// Merge `new` into `last` when both are the same kind of accumulating event.
pub fn try_merge(last: &mut InputEv, new: &InputEv) -> bool {
    match (last, new) {
        (InputEv::MouseRel { dx, dy }, InputEv::MouseRel { dx: ax, dy: ay }) => {
            *dx = dx.saturating_add(*ax);
            *dy = dy.saturating_add(*ay);
            true
        }
        (InputEv::Wheel { dx, dy }, InputEv::Wheel { dx: ax, dy: ay }) => {
            *dx += ax;
            *dy += ay;
            true
        }
        _ => false,
    }
}

/// Merge adjacent relative-motion and wheel events so a backlog never turns into lag.
pub fn coalesce(events: Vec<InputEv>) -> Vec<InputEv> {
    let mut out: Vec<InputEv> = Vec::with_capacity(events.len());
    for ev in events {
        if let Some(last) = out.last_mut() {
            if try_merge(last, &ev) {
                continue;
            }
        }
        out.push(ev);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let m = Msg::Input(InputEv::Key { key: Key::KeyA, down: true });
        assert_eq!(decode(&encode(&m).unwrap()).unwrap(), m);
        let h = Msg::Hello { version: 1, name: "x".into(), width: 1920, height: 1080 };
        assert_eq!(decode(&encode(&h).unwrap()).unwrap(), h);
    }

    #[test]
    fn messages_are_small() {
        let m = Msg::Input(InputEv::MouseRel { dx: -3, dy: 7 });
        assert!(encode(&m).unwrap().len() <= 8);
    }

    #[test]
    fn coalesces_motion_but_keeps_order() {
        let evs = vec![
            InputEv::MouseRel { dx: 1, dy: 1 },
            InputEv::MouseRel { dx: 2, dy: -3 },
            InputEv::Button { button: Button::Left, down: true },
            InputEv::MouseRel { dx: 5, dy: 5 },
            InputEv::Wheel { dx: 0, dy: 1 },
            InputEv::Wheel { dx: 0, dy: 1 },
        ];
        let out = coalesce(evs);
        assert_eq!(
            out,
            vec![
                InputEv::MouseRel { dx: 3, dy: -2 },
                InputEv::Button { button: Button::Left, down: true },
                InputEv::MouseRel { dx: 5, dy: 5 },
                InputEv::Wheel { dx: 0, dy: 2 },
            ]
        );
    }

    #[test]
    fn garbage_does_not_panic() {
        assert!(decode(&[255, 255, 255, 255]).is_err());
    }
}

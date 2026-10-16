//! The open inbox's flood cap: the one refusal its keyless intake makes.
//!
//! Notes are counted per sender and for the inbox as a whole, in hour-long
//! windows. Past either count a note is shed until the window turns, which
//! the route answers as a typed 429 with `retry-after`: pre-auth anonymous
//! shedding, the exception the rate law allows (ARCH-0044 C5). Only a note
//! that lands is counted, so the sender map never holds more senders than the
//! inbox takes in one window.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(3_600);

pub(crate) struct FloodCap {
    per_sender: u32,
    total: u32,
    window: Mutex<Window>,
}

struct Window {
    started: Instant,
    total: u32,
    /// Notes per sender this window. A request whose client address is
    /// unknown is charged to the `None` sender, which all such requests
    /// share.
    senders: HashMap<Option<IpAddr>, u32>,
}

/// A note past the cap; nothing was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Shed {
    /// Until the window turns.
    pub(crate) retry_after: Duration,
}

impl FloodCap {
    pub(crate) fn new(per_sender: u32, total: u32, now: Instant) -> Self {
        Self {
            per_sender,
            total,
            window: Mutex::new(Window {
                started: now,
                total: 0,
                senders: HashMap::new(),
            }),
        }
    }

    /// Counts one note from `sender`, or sheds it.
    pub(crate) fn admit(&self, sender: Option<IpAddr>, now: Instant) -> Result<(), Shed> {
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        if now.duration_since(window.started) >= WINDOW {
            *window = Window {
                started: now,
                total: 0,
                senders: HashMap::new(),
            };
        }
        let key = sender.map(sender_key);
        let sent = window.senders.get(&key).copied().unwrap_or(0);
        if window.total >= self.total || sent >= self.per_sender {
            let left = WINDOW.saturating_sub(now.duration_since(window.started));
            return Err(Shed {
                retry_after: left.max(Duration::from_secs(1)),
            });
        }
        window.total += 1;
        window.senders.insert(key, sent + 1);
        Ok(())
    }
}

/// The bucket a client address is charged to: an IPv6 sender by its /64,
/// which one host or one home network is usually handed whole.
fn sender_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
        v4 => v4,
    }
}

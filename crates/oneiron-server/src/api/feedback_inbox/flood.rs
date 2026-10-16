//! The open inbox's flood cap: the one refusal its keyless intake makes.
//!
//! Attempts are counted per sender and for the inbox as a whole, in
//! hour-long windows. Past either count an attempt is shed until the window turns, which
//! the route answers as a typed 429 with `retry-after`: pre-auth anonymous
//! shedding, the exception the rate law allows (ARCH-0044 C5). Every attempt
//! the cap admits is counted, and a shed one is not, so the sender map never
//! holds more senders than the inbox admits in one window.

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

    /// Counts one attempt from `sender`, or sheds it.
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
            // Whole seconds, rounded up, so a sender who waits that long
            // finds the window turned.
            let left = WINDOW.saturating_sub(now.duration_since(window.started));
            let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
            return Err(Shed {
                retry_after: Duration::from_secs(secs.max(1)),
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

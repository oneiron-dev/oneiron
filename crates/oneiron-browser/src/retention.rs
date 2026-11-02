//! The host's memory floor, as a browser session's live-handle registry
//! meets it (C013). The host decides the budget; the driver only asks it
//! before the registry grows and tells it once the registry shrinks.
//!
//! One charge the host gave may be held in two parts ([`split`]): the
//! driver's live handles and the answers it holds for their later pages
//! (FIX 8007), or a pipe's message read now and the replies parsed from
//! such messages until their calls took them (FIX 7988). The host's charge
//! holds the sum of its parts.

use std::sync::{Arc, Mutex, PoisonError};

/// One session's charge on the host's retained-memory floor for its
/// live-handle registry. Dropping it gives the bytes back.
pub trait HandleRetention: Send {
    /// Moves the charge to `bytes` in all. Shrinking always succeeds;
    /// growth the floor will not admit answers `false` and leaves the
    /// charge as it was.
    fn resize(&mut self, bytes: usize) -> bool;
}

/// `charge` held in two parts, each moving its own bytes: the host's
/// charge holds their sum, and growth of one part the floor will not admit
/// leaves that part as it was. A part dropped gives its bytes back; the
/// charge goes once both did.
pub(crate) fn split(
    charge: Box<dyn HandleRetention>,
) -> (Box<dyn HandleRetention>, Box<dyn HandleRetention>) {
    let shared = Arc::new(Mutex::new(Shared {
        charge,
        parts: [0, 0],
    }));
    let first = Part {
        shared: Arc::clone(&shared),
        at: 0,
    };
    (Box::new(first), Box::new(Part { shared, at: 1 }))
}

/// The host's charge and what each part holds of it.
struct Shared {
    charge: Box<dyn HandleRetention>,
    parts: [usize; 2],
}

/// One part of a split charge.
struct Part {
    shared: Arc<Mutex<Shared>>,
    at: usize,
}

impl HandleRetention for Part {
    fn resize(&mut self, bytes: usize) -> bool {
        let mut shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        let other = shared.parts[1 - self.at];
        if !shared.charge.resize(other.saturating_add(bytes)) {
            return false;
        }
        shared.parts[self.at] = bytes;
        true
    }
}

impl Drop for Part {
    fn drop(&mut self) {
        self.resize(0);
    }
}

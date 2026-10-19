//! Reader pins: a result body a reader holds is never deleted.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The result bodies one vault handle's readers hold, counted by digest. In
/// memory only: no pin outlives the process that reads.
#[derive(Default)]
pub(crate) struct ResultBodyPins {
    counts: Arc<Mutex<PinCounts>>,
}

#[derive(Default)]
struct PinCounts {
    /// Holds on every body at once, by readers of a whole set.
    every: usize,
    bodies: HashMap<[u8; 32], usize>,
    /// The vault instance an off-record body was promoted as, before the
    /// save transaction that names it opened (KS-2A): kept while its pin
    /// is held, read by that transaction.
    promoted: HashMap<[u8; 32], [u8; 16]>,
}

impl PinCounts {
    fn holds(&self, digest: &[u8; 32]) -> bool {
        self.every > 0 || self.bodies.contains_key(digest)
    }
}

fn lock(counts: &Mutex<PinCounts>) -> MutexGuard<'_, PinCounts> {
    counts.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ResultBodyPins {
    /// Pins `digest`, or every body when `None`.
    fn pin(&self, digest: Option<[u8; 32]>) -> ResultBodyPin {
        let mut counts = lock(&self.counts);
        match digest {
            Some(digest) => *counts.bodies.entry(digest).or_insert(0) += 1,
            None => counts.every += 1,
        }
        drop(counts);
        ResultBodyPin {
            counts: Arc::clone(&self.counts),
            digest,
        }
    }

    /// The vault instance the body `digest` was promoted as, while the pin
    /// its promotion took is held.
    pub(crate) fn promoted(&self, digest: &[u8; 32]) -> Option<[u8; 16]> {
        lock(&self.counts).promoted.get(digest).copied()
    }

    /// Whether any reader holds `digest`, or every body.
    pub(crate) fn holds(&self, digest: &[u8; 32]) -> bool {
        lock(&self.counts).holds(digest)
    }

    /// Runs `remove` unless a reader holds `digest`, keeping new pins out
    /// until it returns: the collector's retirement of a body's rows and key
    /// row, then its unlink (FIX 5348). `None` when a reader holds it.
    pub(super) fn unless_pinned<T>(
        &self,
        digest: &[u8; 32],
        remove: impl FnOnce() -> T,
    ) -> Option<T> {
        let counts = lock(&self.counts);
        (!counts.holds(digest)).then(remove)
    }
}

/// One reader's hold on a result body, or on every body, given back when
/// dropped. Taken before the read transaction that finds the body's row and
/// held until its file is closed, it keeps the collector off row and file.
#[must_use = "a body stays pinned only while its pin is held"]
pub(crate) struct ResultBodyPin {
    counts: Arc<Mutex<PinCounts>>,
    digest: Option<[u8; 32]>,
}

impl Drop for ResultBodyPin {
    fn drop(&mut self) {
        let mut counts = lock(&self.counts);
        match self.digest {
            Some(digest) => {
                if let Entry::Occupied(mut held) = counts.bodies.entry(digest) {
                    let left = held.get().saturating_sub(1);
                    if left == 0 {
                        held.remove();
                        counts.promoted.remove(&digest);
                    } else {
                        *held.get_mut() = left;
                    }
                }
            }
            None => counts.every = counts.every.saturating_sub(1),
        }
    }
}

impl crate::Vault {
    /// Pins the result body `digest`: until the pin drops, the collector
    /// leaves its row and file alone. A reader takes it before the read
    /// transaction that finds the body's row and holds it until the file is
    /// closed.
    pub(crate) fn pin_result_body(&self, digest: [u8; 32]) -> ResultBodyPin {
        self.result_body_pins.pin(Some(digest))
    }

    /// [`Self::pin_result_body`] for a body an off-record promotion brought
    /// in as the vault instance `instance`, before the save transaction
    /// that names it opened: that transaction reads the instance while the
    /// pin is held (KS-2A).
    pub(crate) fn pin_promoted_result_body(
        &self,
        digest: [u8; 32],
        instance: [u8; 16],
    ) -> ResultBodyPin {
        let pin = self.result_body_pins.pin(Some(digest));
        lock(&self.result_body_pins.counts)
            .promoted
            .insert(digest, instance);
        pin
    }

    /// Pins every result body at once, for a reader that finds its bodies
    /// inside its read transaction (a checkpoint snapshot, an export). Taken
    /// before that transaction opens, held until its last file is closed.
    pub(crate) fn pin_all_result_bodies(&self) -> ResultBodyPin {
        self.result_body_pins.pin(None)
    }
}
